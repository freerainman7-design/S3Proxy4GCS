package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof" // pprof handlers registered into http.DefaultServeMux, exposed on PPROFAddr when set.
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"s3proxy4gcs/config"
	"s3proxy4gcs/pkg/credstore"
	"s3proxy4gcs/pkg/metrics"
	"s3proxy4gcs/pkg/translate"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"s3proxy4gcs/pkg/reqlog"
)

// maxControlPlaneBodySize is the maximum allowed request body size for
// control-plane PUT operations (Lifecycle, CORS, Logging, Website, Tagging).
// This matches the AWS S3 documented limit of 64 KB for bucket configuration
// XML payloads, preventing memory-exhaustion attacks via oversized bodies.
const maxControlPlaneBodySize = 64 * 1024 // 64 KB

var gcsClient *storage.Client
var gcsCtx context.Context
var readProxy *httputil.ReverseProxy  // GET/HEAD: optimized for download (FlushInterval=-1, large ReadBuffer)
var writeProxy *httputil.ReverseProxy // PUT/POST/DELETE: optimized for upload (large WriteBuffer)
var gcsURL *url.URL

// Global SigV4 signer — reused across all requests to avoid per-request allocation.
var signer = v4.NewSigner()

// hmacCredentials is the in-memory AK→SK mapping used by the Director to
// re-sign each inbound request with the client's own credentials. See
// docs/hmac-credential-mapping-design.md for the architecture. The store
// is populated at startup from config.Config and optionally watched for
// hot reload via fsnotify when config.Config.CredentialsFile is set.
var hmacCredentials = credstore.New()

// resolvedCredsKey is a per-request context key that carries the AWS
// credentials resolved by `handleS3Request` so the Director re-signs
// with the same pair picked during AK validation — avoiding a second
// map lookup on the hot path and guaranteeing the two code sites never
// disagree.
type resolvedCredsKeyType struct{}

var resolvedCredsKey = resolvedCredsKeyType{}

func init() {
	// Prometheus metrics are defined and auto-registered in pkg/metrics.
}

func main() {
	// Initialize configuration
	config.LoadConfig()

	// Initialize request data logger (SOH-delimited CSV via ymlog)
	if config.Config.ReqLogEnabled {
		reqlog.Init(
			config.Config.ReqLogPath,
			config.Config.ReqLogMaxSizeMB,
			config.Config.ReqLogMaxBackup,
			config.Config.ReqLogChanBuf,
		)
		logDir := filepath.Dir(strings.ReplaceAll(config.Config.ReqLogPath, "%Y%M%D", "placeholder"))
		reqlog.StartCleanup(logDir, config.Config.ReqLogKeepDays)
	}

	// Initialize Structured JSON Logger (slog)
	var level slog.Level = slog.LevelInfo
	if config.Config.DebugLogging {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	gcsCtx = context.Background()

	// Fail-fast on missing HMAC re-sign credentials in live mode. Without
	// them the proxy would forward unsigned requests to GCS, triggering
	// 100% 403 rates that are time-consuming to diagnose in production.
	// config.LoadConfig already fatals if no credentials source is set
	// for non-DryRun; here we only seed the atomic store and optionally
	// start the fsnotify hot-reload watcher.
	if len(config.Config.HMACCredentials) > 0 {
		hmacCredentials.Replace(config.Config.HMACCredentials)
	}
	if path := config.Config.CredentialsFile; path != "" {
		if _, err := hmacCredentials.Watch(path, nil); err != nil {
			slog.Error("Failed to start HMAC credentials watcher; continuing with initial snapshot",
				"path", path, "error", err)
		} else {
			slog.Info("HMAC credentials hot-reload enabled", "path", path)
		}
	}

	var err error
	if !config.Config.DryRun {
		var opts []option.ClientOption
		if config.Config.JSONKey != "" {
			opts = append(opts, option.WithCredentialsFile(config.Config.JSONKey))
			slog.Info("Using JSON key for GCS client", "path", config.Config.JSONKey)
		}
		gcsClient, err = storage.NewClient(gcsCtx, opts...)
		if err != nil {
			log.Fatalf("Failed to initialize GCS client: %v", err)
		}
		defer gcsClient.Close()
		log.Println("Initialized real GCS client.")

		// Warmup: pre-fetch metadata of the optional TARGET_BUCKET hint to
		// eagerly resolve credentials and establish the first HTTP/2 connection
		// to GCS. Without this, the very first control-plane request after pod
		// startup may hit a cold-start latency spike (token fetch + TLS
		// handshake) that can exceed SDK retry budgets and surface as 502
		// errors. When TARGET_BUCKET is unset (multi-tenant mode: bucket name
		// is parsed from the incoming request URL), warmup is skipped — the
		// first real request will absorb the cold-start cost.
		if config.Config.TargetBucket != "" {
			warmCtx, warmCancel := context.WithTimeout(gcsCtx, 10*time.Second)
			if _, wErr := gcsClient.Bucket(config.Config.TargetBucket).Attrs(warmCtx); wErr != nil {
				slog.Warn("GCS warmup call failed (non-fatal, will retry on first request)", "error", wErr)
			} else {
				slog.Info("GCS client warmup succeeded", "bucket", config.Config.TargetBucket)
			}
			warmCancel()
		} else {
			slog.Info("GCS client warmup skipped (TARGET_BUCKET not set; bucket name is parsed per-request)")
		}
	} else {
		log.Println("Running in DRY_RUN mode (No real GCS hits).")
	}

	// Initialize Reverse Proxy for passthrough using centralized configuration
	gcsURL, err = url.Parse(config.Config.StorageBaseURL)
	if err != nil {
		log.Fatalf("Failed to parse GCS URL: %v", err)
	}

	// Build shared Transport parameters as a helper to reduce duplication.
	newBaseTransport := func(readBuf, writeBuf int) *http.Transport {
		return &http.Transport{
			MaxIdleConns:          config.Config.MaxIdleConns,
			MaxIdleConnsPerHost:   config.Config.MaxIdleConnsPerHost,
			IdleConnTimeout:       config.Config.IdleConnTimeout,
			ResponseHeaderTimeout: config.Config.ResponseHeaderTimeout,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableCompression:    true, // Preserve Accept-Encoding for S3 signatures
			ForceAttemptHTTP2:     true, // Enable HTTP/2 for multiplexing
			ReadBufferSize:        readBuf,
			WriteBufferSize:       writeBuf,
		}
	}

	// Read-path proxy (GET/HEAD): large read buffer, immediate flush for streaming downloads.
	readProxy = httputil.NewSingleHostReverseProxy(gcsURL)
	// Write-path proxy (PUT/POST/DELETE): large write buffer for upload throughput.
	writeProxy = httputil.NewSingleHostReverseProxy(gcsURL)

	if config.Config.DryRun {
		readProxy.Transport = &dryRunTransport{}
		writeProxy.Transport = &dryRunTransport{}
		slog.Info("Reverse Proxies using DryRun Transport (no real hits)")
	} else {
		readProxy.Transport = newBaseTransport(config.Config.ReadBufferSize, 0)
		writeProxy.Transport = newBaseTransport(0, config.Config.WriteBufferSize)
		slog.Info("Read/Write split Transports initialized",
			"MaxIdleConns", config.Config.MaxIdleConns,
			"MaxIdleConnsPerHost", config.Config.MaxIdleConnsPerHost,
			"IdleConnTimeout", config.Config.IdleConnTimeout,
			"ResponseHeaderTimeout", config.Config.ResponseHeaderTimeout,
			"ReadBufferSize", config.Config.ReadBufferSize,
			"WriteBufferSize", config.Config.WriteBufferSize)
	}

	// FlushInterval on read proxy controls how quickly data is sent to clients.
	// -1 = immediate flush after each Write (best TTFB, more syscalls)
	//  0 = no active flushing (framework-controlled, buffers until full)
	// >0 = periodic flush at the given interval
	// Configurable via FLUSH_INTERVAL_MS; default -1 for streaming downloads.
	switch ms := config.Config.FlushIntervalMS; {
	case ms < 0:
		readProxy.FlushInterval = -1
	case ms == 0:
		// zero value: no periodic flushing
	default:
		readProxy.FlushInterval = time.Duration(ms) * time.Millisecond
	}
	slog.Info("Read proxy FlushInterval configured", "flushIntervalMS", config.Config.FlushIntervalMS)

	// Application-layer BufferPool — controls the buffer size used by
	// ReverseProxy's internal io.CopyBuffer. Using sync.Pool avoids a
	// per-request allocation and significantly reduces GC pressure under
	// high concurrency. The default 32KB matches Go's built-in io.Copy;
	// tune via PROXY_BUFFER_SIZE for large-object throughput workloads.
	if config.Config.ProxyBufferSize > 0 {
		pool := newProxyBufferPool(config.Config.ProxyBufferSize)
		readProxy.BufferPool = pool
		writeProxy.BufferPool = pool
		slog.Info("ReverseProxy BufferPool enabled (sync.Pool)",
			"bufferSize", config.Config.ProxyBufferSize)
	}

	// 预计算虚拟主机后缀，避免每次请求都做字符串拼接。
	// 若 ProxyBaseDomain 未设置则为空字符串，director 内直接跳过虚拟主机转换。
	baseDomainSuffix := ""
	if bd := config.Config.ProxyBaseDomain; bd != "" {
		baseDomainSuffix = "." + bd
	}

	// Shared Director and ModifyResponse applied to both proxies.
	director := func(req *http.Request) {
		// Virtual-hosted style -> path-style conversion.
		// If PROXY_BASE_DOMAIN is set, detect requests like:
		//   Host: bucket.s3proxy.example.com  GET /key
		// and rewrite to:
		//   GET /bucket/key
		// This allows SDK clients to use default virtual-hosted addressing
		// without configuring path-style, enabling seamless S3-to-GCS migration.
		if baseDomainSuffix != "" {
			host := req.Host
			// 用 net.SplitHostPort 剥离端口，正确处理 IPv6 地址（如 [::1]:8080）。
			// 若 host 不含端口，SplitHostPort 会返回错误，此时直接使用原始 host。
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if strings.HasSuffix(host, baseDomainSuffix) {
				bucket := strings.TrimSuffix(host, baseDomainSuffix)
				if bucket != "" {
					req.URL.Path = "/" + bucket + req.URL.Path
					// Also fix RawPath if set (supports URL-encoded keys)
					if req.URL.RawPath != "" {
						req.URL.RawPath = "/" + bucket + req.URL.RawPath
					}
					if config.Config.DebugLogging {
						slog.Debug("Virtual-hosted to path-style conversion",
							"bucket", bucket,
							"rewrittenPath", req.URL.Path)
					}
				}
			}
		}

		req.URL.Host = gcsURL.Host
		req.URL.Scheme = gcsURL.Scheme
		req.Host = gcsURL.Host // Critical for TLS Handshake

		if config.Config.DebugLogging {
			headers := req.Header.Clone()
			headers.Del("Authorization")
			slog.Debug("Request Headers transmitted to GCS (Redacted)", "headers", headers)
		}

		if clStr := req.Header.Get("Content-Length"); clStr != "" {
			if cl, err := strconv.ParseInt(clStr, 10, 64); err == nil {
				req.ContentLength = cl
			}
		}

		// 1. Storage Class Translation & x-id Stripping (Hybrid Data-Plane)
		// Always re-sign: the Director changes Host from proxy to GCS,
		// so the original SigV4 signature (signed for localhost) is invalid.

		sc := req.Header.Get("x-amz-storage-class")
		if sc != "" && sc != "STANDARD" {
			if config.Config.DebugLogging {
				slog.Debug("Detected non-standard S3 Storage Class", "storageClass", sc)
			}
			// Translation table: S3 -> GCS. Entries must stay in sync with
			// `isKnownS3StorageClass` below. Unknown values are rejected at
			// the handler entry point (handleS3Request) before we get here.
			gcsSC, known := translateS3StorageClass(sc)
			if known {
				req.Header.Set("x-amz-storage-class", gcsSC)
			}
		}

		// Detect x-id query parameter (Go SDK v2 specific tracking)
		q := req.URL.Query()
		if xid := q.Get("x-id"); xid != "" {
			if config.Config.DebugLogging {
				slog.Debug("Detected x-id query parameter. Stripping and re-signing", "xId", xid)
			}
			q.Del("x-id")
			req.URL.RawQuery = q.Encode()
		}

		// Detect Accept-Encoding: identity (causes issues with GCS S3 API)
		if !config.Config.DisableHeaderStrip && req.Header.Get("Accept-Encoding") == "identity" {
			if config.Config.DebugLogging {
				slog.Debug("Detected Accept-Encoding: identity. Stripping and re-signing")
			}
			req.Header.Del("Accept-Encoding")
		}

		{
			// Prefer per-request credentials resolved at handleS3Request time
			// (the client's own AK/SK, looked up against the mapping store).
			// Fall back to the legacy single-pair when the mapping is empty
			// or the request took the non-validated path (e.g. DryRun unit
			// tests that never populate the store).
			awsCreds, haveCreds := credentialsFromContext(req.Context())
			if !haveCreds {
				if config.Config.ProxyAccessKey == "" || config.Config.ProxySecretKey == "" {
					slog.Warn("Proxy HMAC credentials not set! Re-signing skipped. Signature will fail at GCS.")
					return
				}
				awsCreds = aws.Credentials{
					AccessKeyID:     config.Config.ProxyAccessKey,
					SecretAccessKey: config.Config.ProxySecretKey,
				}
			}

			// Always use UNSIGNED-PAYLOAD for re-signing.
			// Some SDKs (Go V1, Java V2) compute the actual body SHA256,
			// but GCS HMAC may not verify body hashes correctly through
			// the reverse proxy. UNSIGNED-PAYLOAD works universally.
			payloadHash := "UNSIGNED-PAYLOAD"
			req.Header.Set("X-Amz-Content-Sha256", payloadHash)

			// Unconditionally strip headers that MUST NOT appear in the
			// canonical request we sign for GCS. These three are special:
			//
			//   * Accept-Encoding  — Go's stdlib http.Transport auto-adds
			//     `Accept-Encoding: gzip` when the caller did not set it,
			//     and Google's front-end rewrites the value on the wire to
			//     `gzip,gzip(gfe)`. Either way the value reaching GCS is
			//     not the one we signed → SignatureDoesNotMatch.
			//   * Amz-Sdk-Invocation-Id / Amz-Sdk-Request — added by the
			//     AWS SDK v2 middleware chain and known to be stripped or
			//     rewritten by Go's client transport in some code paths.
			//
			// Clients cannot reliably prevent these from reaching the
			// proxy (see docs/sdk-client-config.md), so the proxy removes
			// them right before signing regardless of DISABLE_HEADER_STRIP.
			req.Header.Del("User-Agent")
			req.Header.Del("Expect")
			req.Header.Del("Accept-Encoding")
			req.Header.Del("Amz-Sdk-Invocation-Id")
			req.Header.Del("Amz-Sdk-Request")
			if !config.Config.DisableHeaderStrip {
				req.Header.Del("X-Amz-Decoded-Content-Length")
				req.Header.Del("X-Amz-Trailer")
				if ce := req.Header.Get("Content-Encoding"); strings.Contains(ce, "aws-chunked") {
					req.Header.Del("Content-Encoding")
				}
			}

			// For POST ?delete (DeleteObjects), GCS requires Content-MD5.
			// Stream-compute MD5 from body using io.TeeReader (single pass).
			if req.Method == http.MethodPost && req.URL.Query().Has("delete") && req.Body != nil {
				var buf bytes.Buffer
				var h hash.Hash = md5.New()
				_, readErr := io.Copy(&buf, io.TeeReader(req.Body, h))
				req.Body.Close()
				if readErr == nil {
					req.Header.Set("Content-Md5", base64.StdEncoding.EncodeToString(h.Sum(nil)))
					req.Body = io.NopCloser(&buf)
					req.ContentLength = int64(buf.Len())
					if config.Config.DebugLogging {
						slog.Debug("Computed Content-MD5 for POST ?delete",
							"bodyLen", buf.Len(),
							"md5", req.Header.Get("Content-Md5"))
					}
				}
			} else {
				req.Header.Del("Content-Md5")
			}

			// Debug: log all headers before re-signing (temporary)
			if config.Config.DebugLogging {
				for k, v := range req.Header {
					slog.Debug("Pre-sign header", "key", k, "value", v)
				}
			}

			signStart := time.Now()
			signErr := signer.SignHTTP(req.Context(), awsCreds, req, payloadHash, "s3", "us-east-1", time.Now())
			metrics.ResignDurationSeconds.Observe(time.Since(signStart).Seconds())
			if signErr != nil {
				slog.Error("Failed to re-sign request", "error", signErr)
			} else if config.Config.DebugLogging {
				// Debug-only: signed request trace. Authorization intentionally redacted.
				slog.Debug("Successfully re-signed request for GCS",
					"method", req.Method,
					"url", req.URL.String(),
					"host", req.Host,
					"content-length", req.ContentLength,
					"content-type", req.Header.Get("Content-Type"),
					"x-amz-sha256", req.Header.Get("X-Amz-Content-Sha256"),
				)
			}
		}
	}

	modifyResponse := func(resp *http.Response) error {
		if config.Config.DebugLogging {
			slog.Debug("Response Headers received from GCS", "headers", resp.Header)
		}

		// Log 4xx/5xx errors from GCS for debugging.
		// Do NOT read the body: many 4xx are normal (HeadObject 404,
		// GetObjectTagging 403). Reading the body here breaks streaming
		// and wastes allocations on the hot path. The status code and URL
		// are enough; detailed error bodies are visible to clients anyway.
		if resp.StatusCode >= 400 {
			slog.Warn("GCS returned error",
				"status", resp.StatusCode,
				"method", resp.Request.Method,
				"url", resp.Request.URL.String(),
			)
		}

		// Debug-only: full XML dump for ListObjectVersions. Guarded by
		// DebugLogging — otherwise we must NOT ReadAll, since the body
		// can be multi-MB on buckets with large version histories.
		if config.Config.DebugLogging && strings.Contains(resp.Request.URL.RawQuery, "versions") {
			if bodyBytes, err := io.ReadAll(resp.Body); err == nil {
				slog.Debug("XML Response Body for ListObjectVersions", "xml", string(bodyBytes))
				resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		}

		// 3. Versioning Interop (Ingress)
		if gen := resp.Header.Get("x-goog-generation"); gen != "" {
			resp.Header.Set("x-amz-version-id", gen)
			if config.Config.DebugLogging {
				slog.Debug("Mapped x-goog-generation to x-amz-version-id", "generation", gen)
			}
		}

		return nil
	}

	// Apply shared Director and ModifyResponse to both proxies.
	readProxy.Director = director
	readProxy.ModifyResponse = modifyResponse
	writeProxy.Director = director
	writeProxy.ModifyResponse = modifyResponse

	r := chi.NewRouter()

	// Base middlewares.
	//
	// chi's default middleware.Logger is intentionally NOT used: it emits
	// plain-text access logs that duplicate observabilityMiddleware's
	// structured JSON output. Dropping it cuts ~30% of per-request log
	// bytes at high QPS (and the matching Cloud Logging cost).
	r.Use(middleware.RequestID)
	if config.Config.ReqLogEnabled {
		r.Use(reqlog.Middleware(reqlog.Default))
	}
	r.Use(middleware.Recoverer)
	// metrics.WithMetrics records bytes/size/count/duration for every proxy
	// request. Placed before observability logging so status codes are captured
	// consistently.
	r.Use(metrics.WithMetrics)
	r.Use(observabilityMiddleware)

	// Concurrency limiter — prevents goroutine/connection exhaustion under burst load.
	// Requests exceeding the limit receive 503 Service Unavailable.
	// Configurable via MAX_CONCURRENT_REQUESTS (default 1000, 0 = disabled).
	if config.Config.MaxConcurrentRequests > 0 {
		r.Use(middleware.Throttle(config.Config.MaxConcurrentRequests))
		slog.Info("Concurrency throttle enabled", "max_concurrent_requests", config.Config.MaxConcurrentRequests)
	} else {
		slog.Warn("Concurrency throttle DISABLED (MAX_CONCURRENT_REQUESTS=0)")
	}

	// Operational endpoints (excluded from S3 routing).
	// Each endpoint is registered only when its feature flag is enabled so
	// the catch-all S3 route never picks up /health or /readyz. When a flag
	// is off we register a 404 stub to avoid the request being classified as
	// a bucket-level S3 call by the metrics endpoint label.
	if config.Config.Features.HealthEndpoint {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})
	} else {
		r.Get("/health", featureDisabled404("health_endpoint"))
	}

	if config.Config.Features.ReadyzEndpoint {
		r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
			if config.Config.DryRun {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ready","mode":"dry_run"}`))
				return
			}
			if gcsClient == nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"status":"not_ready","reason":"gcs_client_nil"}`))
				return
			}
			// TARGET_BUCKET is an optional hint used for active probing. In
			// multi-tenant mode (no hint configured) we only verify that the
			// GCS client is alive — the first real request will surface any
			// per-bucket auth/permission failure with a proper S3 error code.
			if config.Config.TargetBucket == "" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ready","mode":"live","probe":"client_only"}`))
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			_, err := gcsClient.Bucket(config.Config.TargetBucket).Attrs(ctx)
			if err != nil {
				slog.Error("Readiness check failed", "error", err)
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"status":"not_ready","reason":"gcs_connectivity_failed"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ready","mode":"live","probe":"target_bucket"}`))
		})
	} else {
		r.Get("/readyz", featureDisabled404("readyz_endpoint"))
	}

	// Pass-through or intercept handlers
	r.Route("/", func(r chi.Router) {
		// Catch-all for S3 requests
		r.Get("/*", handleS3Request)
		r.Put("/*", handleS3Request)
		r.Post("/*", handleS3Request)
		r.Delete("/*", handleS3Request)
		r.Head("/*", handleS3Request)
	})

	// Root mux keeps /metrics fully outside the proxy/middleware chain so
	// Prometheus scrapes are never accounted for as S3 traffic and are not
	// affected by the throttle or observability middleware.
	rootMux := http.NewServeMux()
	if config.Config.Features.MetricsEndpoint {
		rootMux.Handle("/metrics", promhttp.Handler())
	} else {
		// When disabled we still claim the path so a request for /metrics is
		// returned as a 404 rather than being delegated to chi and parsed as
		// a bucket-level S3 call (which would pollute request metrics).
		rootMux.HandleFunc("/metrics", featureDisabled404("metrics_endpoint"))
	}
	rootMux.Handle("/", r)

	srv := &http.Server{
		Addr:    ":" + config.Config.Port,
		Handler: rootMux,

		// Timeout settings aligned with AWS SDK for Go v2 defaults:
		// - ReadHeaderTimeout: matches SDK's TLSHandshakeTimeout (10s), prevents Slowloris attacks
		// - IdleTimeout: matches SDK's IdleConnTimeout (90s), releases idle keep-alive connections
		// - ReadTimeout/WriteTimeout: intentionally unset (0) to support data-plane streaming
		//   of large objects (S3 max 50TB), consistent with SDK not setting Client.Timeout
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	serverErrors := make(chan error, 1)

	// Optional pprof endpoint on a dedicated port.
	//
	// net/http/pprof registers its handlers onto http.DefaultServeMux in
	// its init(); we expose that mux on a SEPARATE listener so profiling
	// data never competes with data-plane traffic or leaks through the
	// public LoadBalancer. Intended for cluster-local bind only
	// (e.g. "127.0.0.1:6060"); operators port-forward to access.
	if addr := config.Config.PPROFAddr; addr != "" {
		go func() {
			slog.Info("Starting pprof endpoint (DEBUG)", "addr", addr)
			pprofSrv := &http.Server{
				Addr:              addr,
				Handler:           http.DefaultServeMux,
				ReadHeaderTimeout: 10 * time.Second,
			}
			if err := pprofSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("pprof server exited", "error", err)
			}
		}()
	}

	go func() {
		slog.Info("Starting S3 to GCS proxy", "port", config.Config.Port, "disable_header_strip", config.Config.DisableHeaderStrip)
		if !config.Config.DisableHeaderStrip {
			slog.Warn("DISABLE_HEADER_STRIP=false — Director will strip SDK-diagnostic headers (Amz-Sdk-*, Accept-Encoding, aws-chunked) before re-signing. This is the legacy behaviour; default since v1.8 is true (clients handle their own headers).")
		}
		serverErrors <- srv.ListenAndServe()
	}()

	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		slog.Error("Server error on startup", "error", err)
		return
	case sig := <-shutdownSignal:
		slog.Info("Shutdown signal received", "signal", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("Shutdown failed, forcing close", "error", err)
			srv.Close()
		} else {
			slog.Info("Server gracefully stopped")
		}
	}
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
//
// It exposes Unwrap() and Flush() so that httputil.ReverseProxy's use of
// http.NewResponseController can walk through this wrapper to reach the
// underlying http.Flusher. Without this, readProxy.FlushInterval = -1
// silently fails and GET/HEAD streaming buffers at the proxy boundary.

// proxyBufferPool implements httputil.BufferPool using sync.Pool to provide
// reusable byte slices for ReverseProxy's internal io.CopyBuffer calls.
// This eliminates per-request heap allocations and reduces GC pressure
// under high concurrency. See PROXY_BUFFER_SIZE in config.
type proxyBufferPool struct {
	pool sync.Pool
}

func newProxyBufferPool(size int) *proxyBufferPool {
	return &proxyBufferPool{
		pool: sync.Pool{
			New: func() any { return make([]byte, size) },
		},
	}
}

func (p *proxyBufferPool) Get() []byte  { return p.pool.Get().([]byte) }
func (p *proxyBufferPool) Put(b []byte) { p.pool.Put(b) }

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController traverse to the real ResponseWriter
// (Go 1.20+ convention).
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// Flush proxies to the underlying writer's Flusher implementation, enabling
// immediate response flushing for streaming GET/HEAD downloads.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// observabilityMiddleware replaces chi's default Logger middleware with structured
// JSON logging that includes request_id, source_ip, method, path, status, duration,
// body size, and — when present — access_key and guploader_upload_id.
// It also records Prometheus metrics for every request.
func observabilityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		duration := time.Since(start)
		reqID := middleware.GetReqID(r.Context())

		// Determine handler label for metrics
		handlerLabel := "proxy"
		q := r.URL.Query()
		for _, key := range []string{"lifecycle", "cors", "logging", "website", "tagging"} {
			if _, ok := q[key]; ok {
				handlerLabel = key
				break
			}
		}
		if handlerLabel == "proxy" {
			if _, ok := q["restore"]; ok && r.Method == http.MethodPost {
				handlerLabel = "restore"
			}
		}

		// Extract client identity and GCS trace ID for structured logging.
		sourceIP := reqlog.ExtractSourceIP(r)
		accessKey := reqlog.ExtractAccessKey(r)
		guploaderID := reqlog.ExtractGUploaderUploadID(rec.Header())

		fields := []any{
			"request_id", reqID,
			"source_ip", sourceIP,
			"method", r.Method,
			"uri", r.RequestURI,
			"status", rec.status,
			"duration_ms", duration.Milliseconds(),
			"content_length", r.ContentLength,
			"handler", handlerLabel,
		}
		if accessKey != "" {
			fields = append(fields, "access_key", accessKey)
		}
		if guploaderID != "" {
			fields = append(fields, "guploader_upload_id", guploaderID)
		}

		slog.Info("HTTP request completed", fields...)
	})
}

// reqLogger returns a slog.Logger enriched with the request_id from context.
func reqLogger(ctx context.Context) *slog.Logger {
	reqID := middleware.GetReqID(ctx)
	if reqID == "" {
		return slog.Default()
	}
	return slog.Default().With("request_id", reqID)
}

// featureDisabled404 returns an http.HandlerFunc that records the rejection
// in `s3proxy_feature_disabled_rejections_total{feature=...}` and responds
// with a plain 404. Used for operational endpoints (`/health`, `/readyz`,
// `/metrics`) whose consumers are K8s kubelets and Prometheus — neither
// parses S3 XML error bodies, so a minimal text 404 is sufficient and
// avoids suggesting the path is a valid bucket.
func featureDisabled404(feature string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics.FeatureDisabledRejections.WithLabelValues(feature).Inc()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "endpoint %q is disabled on this proxy\n", feature)
	}
}

// ensureFeatureEnabled returns true when the operation is allowed. When
// disabled it writes a `501 NotImplemented` S3 error, logs a WARN and
// increments `s3proxy_feature_disabled_rejections_total{feature=...}`.
//
// Every feature-flag branch (control plane subresource, data-plane composite,
// operational endpoint) MUST call this helper so the rejection path is
// uniform: same status code, same XML schema, same metric. Status 501 is
// used — rather than 403 — because AWS SDKs interpret 403 as an
// authentication problem and may enter a retry/refresh loop, whereas 501 is
// terminal for compatibility callers.
func ensureFeatureEnabled(w http.ResponseWriter, r *http.Request, enabled bool, feature string) bool {
	if enabled {
		return true
	}
	metrics.FeatureDisabledRejections.WithLabelValues(feature).Inc()
	reqLogger(r.Context()).Warn("Feature disabled by configuration",
		"feature", feature,
		"method", r.Method,
		"uri", r.RequestURI,
	)
	writeS3Error(w, http.StatusNotImplemented, "NotImplemented",
		fmt.Sprintf("The %q operation is disabled on this proxy.", feature))
	return false
}

// timeGCSCall executes a GCS SDK call with an optional per-call timeout,
// logs and records its duration. The fn receives a context that may have
// a deadline applied (controlled by GCS_CALL_TIMEOUT_SEC, default 30s).
//
// On failure the call also records s3proxy_gcs_errors_total with a
// status_class label derived from googleapi.Error or the standard ctx
// cancellation / deadline reasons.
func timeGCSCall(ctx context.Context, operation string, fn func(ctx context.Context) error) error {
	callCtx := ctx
	if config.Config.GCSCallTimeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, config.Config.GCSCallTimeout)
		defer cancel()
	}

	start := time.Now()
	err := fn(callCtx)
	duration := time.Since(start)
	metrics.GCSAPIDurationSeconds.WithLabelValues(operation).Observe(duration.Seconds())
	log := reqLogger(ctx)
	if err != nil {
		class := classifyGCSSDKError(err)
		metrics.GCSErrorsTotal.WithLabelValues(operation, class).Inc()
		log.Error("GCS API call failed",
			"operation", operation,
			"duration_ms", duration.Milliseconds(),
			"status_class", class,
			"error", err)
	} else {
		log.Info("GCS API call succeeded", "operation", operation, "duration_ms", duration.Milliseconds())
	}
	return err
}

// classifyGCSSDKError maps a GCS SDK error into a low-cardinality label
// suitable for s3proxy_gcs_errors_total{status_class=…}.
func classifyGCSSDKError(err error) string {
	if err == nil {
		return ""
	}
	var gErr *googleapi.Error
	if errors.As(err, &gErr) {
		if class := metrics.ClassifyGCSError(gErr.Code); class != "" {
			return class
		}
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "network"
	}
}

// translateS3StorageClass maps an S3 storage class to its GCS equivalent.
// The second return value is false for values the proxy does not recognise;
// callers MUST treat those as client errors (InvalidStorageClass).
//
// Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html
func translateS3StorageClass(sc string) (string, bool) {
	switch sc {
	case "STANDARD", "REDUCED_REDUNDANCY":
		// REDUCED_REDUNDANCY is deprecated on AWS and silently promoted
		// to STANDARD. Match that behaviour so callers don't see surprise
		// Class A cost increases.
		return "STANDARD", true
	case "STANDARD_IA", "ONEZONE_IA":
		return "NEARLINE", true
	case "GLACIER_IR":
		return "COLDLINE", true
	case "GLACIER", "DEEP_ARCHIVE":
		return "ARCHIVE", true
	case "INTELLIGENT_TIERING":
		return "AUTOCLASS", true
	default:
		return "", false
	}
}

// credentialsFromContext extracts the AWS credentials stashed into the
// request context by validateClientCredential. The boolean is false when
// no credentials were resolved (e.g. the store is empty and the request
// is routed through the legacy single-key fallback).
func credentialsFromContext(ctx context.Context) (aws.Credentials, bool) {
	v, ok := ctx.Value(resolvedCredsKey).(aws.Credentials)
	return v, ok
}

// validateClientCredential inspects the SigV4 Authorization header,
// looks the access key up in the in-memory credential store and returns
// the resolved credentials. It short-circuits with an S3-compatible
// error response when:
//
//   - the store is non-empty but the request carries no Authorization
//     header → 403 AccessDenied
//   - the store is non-empty and the AK is not found → 403 InvalidAccessKeyId
//
// When the store is empty (no HMAC_CREDENTIALS / HMAC_CREDENTIALS_FILE
// configured and no legacy single-key either) the function returns
// ok=false so the caller can either fall back to the legacy single-key
// path (if HMACStrict=false) or proceed unvalidated (DryRun local tests).
func validateClientCredential(w http.ResponseWriter, r *http.Request) (aws.Credentials, bool) {
	if hmacCredentials.Size() == 0 {
		metrics.HMACCredentialLookups.WithLabelValues("disabled").Inc()
		return aws.Credentials{}, false
	}

	authz := r.Header.Get("Authorization")
	ak, err := credstore.ExtractAccessKey(authz)
	if err != nil {
		// Fall back to presigned URL query-param credentials before giving up.
		if qak, qerr := credstore.ExtractAccessKeyFromQuery(r.URL.RawQuery); qerr == nil {
			ak = qak
		} else {
			metrics.HMACCredentialLookups.WithLabelValues("no_auth").Inc()
			reqLogger(r.Context()).Warn("Rejecting request without SigV4 credential",
				"method", r.Method, "uri", r.RequestURI)
			writeS3Error(w, http.StatusForbidden, "AccessDenied",
				"Request is missing a valid SigV4 Authorization header.")
			return aws.Credentials{}, false
		}
	}

	sk, found := hmacCredentials.Lookup(ak)
	if !found {
		metrics.HMACCredentialLookups.WithLabelValues("miss").Inc()
		reqLogger(r.Context()).Warn("Rejecting request with unknown access key",
			"ak", ak, "method", r.Method, "uri", r.RequestURI)
		writeS3Error(w, http.StatusForbidden, "InvalidAccessKeyId",
			"The AWS Access Key Id you provided does not exist in our records.")
		return aws.Credentials{}, false
	}

	metrics.HMACCredentialLookups.WithLabelValues("hit").Inc()
	creds := aws.Credentials{AccessKeyID: ak, SecretAccessKey: sk}
	*r = *r.WithContext(context.WithValue(r.Context(), resolvedCredsKey, creds))
	return creds, true
}

func handleS3Request(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())
	log.Info("Received S3 Request", "method", r.Method, "uri", r.RequestURI)

	// Credential mapping gate: if a per-client AK→SK store is configured,
	// every request must carry a SigV4 credential that maps to a known
	// secret before any handler runs. Turning it off is only possible by
	// leaving HMAC_CREDENTIALS{,_FILE} unset, which degrades to the
	// legacy single-key re-sign path — useful for local DryRun tests and
	// the pre-v1.7 deployments tracked in docs/hmac-credential-mapping-design.md.
	if hmacCredentials.Size() > 0 {
		if _, ok := validateClientCredential(w, r); !ok {
			return
		}
	}

	// Fail fast on unknown x-amz-storage-class values. Previously we
	// silently remapped them to NEARLINE, which violated AGENTS rule 4
	// ("Reject Unsupported") and risked placing hot data on cheaper tiers
	// without the caller's knowledge. The Director still rewrites known
	// values in-place for SigV4 continuity.
	if sc := r.Header.Get("x-amz-storage-class"); sc != "" {
		if _, ok := translateS3StorageClass(sc); !ok {
			log.Warn("Rejecting unknown S3 storage class",
				"storage_class", sc,
				"method", r.Method,
				"uri", r.RequestURI)
			writeS3Error(w, http.StatusBadRequest, "InvalidStorageClass",
				fmt.Sprintf("The storage class %q is not recognised. Supported values: STANDARD, REDUCED_REDUNDANCY, STANDARD_IA, ONEZONE_IA, GLACIER_IR, GLACIER, DEEP_ARCHIVE, INTELLIGENT_TIERING.", sc))
			return
		}
	}

	// Reject aws-chunked requests early.
	// Modern AWS SDKs (Go V2, Python boto3, Java V2) may default to Flexible Checksums,
	// which wraps the payload in aws-chunked Transfer-Encoding with checksum trailers.
	// GCS does not support aws-chunked framing, causing silent signature or body-parse failures.
	// Users must set AWS_REQUEST_CHECKSUM_CALCULATION=WHEN_REQUIRED on their SDK client.
	if ce := r.Header.Get("Content-Encoding"); strings.Contains(ce, "aws-chunked") {
		log.Warn("Rejected aws-chunked request: GCS does not support Flexible Checksums trailers. "+
			"Client must set AWS_REQUEST_CHECKSUM_CALCULATION=WHEN_REQUIRED",
			"content-encoding", ce,
			"method", r.Method,
			"uri", r.RequestURI,
			"user-agent", r.Header.Get("User-Agent"),
		)
		writeS3Error(w, http.StatusBadRequest, "InvalidRequest",
			"This proxy does not support aws-chunked Transfer-Encoding (Flexible Checksums). "+
				"Please set the environment variable AWS_REQUEST_CHECKSUM_CALCULATION=WHEN_REQUIRED "+
				"or configure your SDK client to disable automatic checksum trailers.")
		return
	}

	// Parse the query string once and reuse. Calling r.URL.Query() multiple
	// times reparses the RawQuery each invocation. Previously we paid for
	// 5+ parses per request (lifecycle/cors/logging/website/tagging).
	q := r.URL.Query()
	hasQueryParam := func(key string) bool {
		for k := range q {
			if strings.EqualFold(k, key) {
				return true
			}
		}
		return false
	}

	// Check if this is a lifecycle request
	if hasQueryParam("lifecycle") {
		if !ensureFeatureEnabled(w, r, config.Config.Features.Lifecycle, "lifecycle") {
			return
		}
		if r.Method == http.MethodPut {
			handlePutLifecycle(w, r)
			return
		} else if r.Method == http.MethodGet {
			handleGetLifecycle(w, r)
			return
		} else if r.Method == http.MethodDelete {
			handleDeleteLifecycle(w, r)
			return
		}
	}

	// Check if this is a CORS request
	if hasQueryParam("cors") {
		if !ensureFeatureEnabled(w, r, config.Config.Features.CORS, "cors") {
			return
		}
		if r.Method == http.MethodPut {
			handlePutCORS(w, r)
			return
		} else if r.Method == http.MethodGet {
			handleGetCORS(w, r)
			return
		} else if r.Method == http.MethodDelete {
			handleDeleteCORS(w, r)
			return
		}
	}

	// Check if this is a Logging request
	if hasQueryParam("logging") {
		if !ensureFeatureEnabled(w, r, config.Config.Features.Logging, "logging") {
			return
		}
		if r.Method == http.MethodPut {
			handlePutLogging(w, r)
			return
		} else if r.Method == http.MethodGet {
			handleGetLogging(w, r)
			return
		} else if r.Method == http.MethodDelete {
			handleDeleteLogging(w, r)
			return
		}
	}

	// Check if this is a Website request
	if hasQueryParam("website") {
		if !ensureFeatureEnabled(w, r, config.Config.Features.Website, "website") {
			return
		}
		if r.Method == http.MethodPut {
			handlePutWebsite(w, r)
			return
		} else if r.Method == http.MethodGet {
			handleGetWebsite(w, r)
			return
		} else if r.Method == http.MethodDelete {
			handleDeleteWebsite(w, r)
			return
		}
	}

	// Check if this is a Tagging request
	if hasQueryParam("tagging") {
		if !ensureFeatureEnabled(w, r, config.Config.Features.Tagging, "tagging") {
			return
		}
		if r.Method == http.MethodPut {
			handlePutObjectTagging(w, r)
			return
		} else if r.Method == http.MethodGet {
			handleGetObjectTagging(w, r)
			return
		} else if r.Method == http.MethodDelete {
			handleDeleteObjectTagging(w, r)
			return
		}
	}

	// Check if this is a RestoreObject request. GCS objects in every storage
	// class are always directly readable, so there is no real "thaw" step to
	// perform; we synthesise an S3-compatible success response so legacy
	// clients that still call RestoreObject keep working without changes.
	if hasQueryParam("restore") {
		if !ensureFeatureEnabled(w, r, config.Config.Features.RestoreObject, "restore_object") {
			return
		}
		if r.Method == http.MethodPost {
			handleRestoreObject(w, r)
			return
		}
		// Non-POST verbs on ?restore are not defined by S3; refuse instead of
		// silently falling through to the data-plane proxy (AGENTS rule 4).
		writeS3Error(w, http.StatusNotImplemented, "NotImplemented",
			"Only POST /<bucket>/<key>?restore is supported for the RestoreObject operation.")
		return
	}

	// Data-plane composite gates (AGENTS rule 4 compatibility exception):
	// reject high-cost operations when disabled so operators can lock the
	// proxy down to basic CRUD without relying on IAM. Basic Get/Put/Head/
	// Delete/List/ListBuckets intentionally have NO toggle — disabling them
	// would break the proxy as a service and is better handled at the
	// network / IAM layer.

	// CopyObject: detected by the `x-amz-copy-source` header on a PUT.
	// Covers both plain CopyObject and UploadPartCopy (whose PUT also
	// carries x-amz-copy-source; the header, not the uploadId, is what
	// triggers the server-side copy path on GCS).
	if r.Method == http.MethodPut && r.Header.Get("x-amz-copy-source") != "" {
		if !ensureFeatureEnabled(w, r, config.Config.Features.CopyObject, "copy_object") {
			return
		}
	}

	// Multipart Upload family: CreateMultipartUpload (?uploads),
	// UploadPart / UploadPartCopy (?partNumber&uploadId), Complete / Abort
	// (?uploadId), ListMultipartUploads (?uploads on bucket).
	if hasQueryParam("uploads") || hasQueryParam("uploadId") || hasQueryParam("partNumber") {
		if !ensureFeatureEnabled(w, r, config.Config.Features.MultipartUpload, "multipart_upload") {
			return
		}
	}

	// Bulk DeleteObjects: POST /<bucket>?delete. Distinct from single-object
	// DELETE /<bucket>/<key>, which stays always-on.
	if r.Method == http.MethodPost && hasQueryParam("delete") {
		if !ensureFeatureEnabled(w, r, config.Config.Features.DeleteObjects, "delete_objects") {
			return
		}
	}

	// Default: Fallthrough to Reverse Proxy
	// Route to read or write proxy based on HTTP method.
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		readProxy.ServeHTTP(w, r)
	default:
		writeProxy.ServeHTTP(w, r)
	}
}

type dryRunTransport struct{}

func (t *dryRunTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	slog.Info("[DRY_RUN] ReverseProxy intercepted", "method", req.Method, "url", req.URL.String())
	slog.Debug("[DRY_RUN] Header StorageClass", "class", req.Header.Get("x-amz-storage-class"))

	// Return a synthetic response. resp.Request MUST be populated,
	// otherwise httputil.ReverseProxy.modifyResponse will nil-deref when
	// it inspects resp.Request.URL / resp.Request.Method.
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("Successfully proxied to GCS (DryRun - no real hits).")),
		Request:    req,
	}

	return resp, nil
}

// parseBucketFromPath extracts the bucket name from the first path segment
// of the request URL (path-style S3 addressing). Returns the bucket name and
// true on success; on failure it writes a 400 InvalidArgument S3 error and
// returns false, letting the caller return immediately. Used by every
// bucket-level control-plane handler (lifecycle / CORS / logging / website)
// so the proxy honours whatever bucket the client addressed in the URL
// instead of the legacy single-tenant TARGET_BUCKET fallback.
func parseBucketFromPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) == 0 || pathParts[0] == "" {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Bucket name required.")
		return "", false
	}
	return pathParts[0], true
}

func handlePutLifecycle(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())

	var s3Cfg translate.LifecycleConfiguration
	if !decodeControlPlaneXML(w, r, "lifecycle", &s3Cfg) {
		return
	}

	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}

	// Translate S3 XML directly to GCS SDK Lifecycle struct.
	storageLifecycle, err := translate.TranslateS3ToGCSLifecycle(&s3Cfg)
	if err != nil {
		log.Error("Failed to translate lifecycle to GCS SDK", "error", err)
		writeS3Error(w, http.StatusBadRequest, "InvalidRequest", err.Error())
		return
	}

	// 4. If DryRun is true, return success without calling GCS
	if config.Config.DryRun {
		w.WriteHeader(http.StatusOK)
		return
	}

	// 5. Execute Bucket Update via GCS SDK
	bucket := gcsClient.Bucket(targetBucket)
	uattrs := storage.BucketAttrsToUpdate{
		Lifecycle: storageLifecycle,
	}

	err = timeGCSCall(r.Context(), "PutBucketLifecycle", func(ctx context.Context) error {
		_, e := bucket.Update(ctx, uattrs)
		return e
	})
	if err != nil {
		log.Error("GCS API call failed for PutBucketLifecycle", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to update lifecycle configuration on GCS.")
		return
	}

	log.Info("Successfully updated GCS bucket lifecycle", "bucket", targetBucket)
	w.WriteHeader(http.StatusOK)
}

func handleGetLifecycle(w http.ResponseWriter, r *http.Request) {
	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}
	if config.Config.DryRun {
		writeS3Error(w, http.StatusNotFound, "NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist.")
		return
	}
	bucket := gcsClient.Bucket(targetBucket)
	var attrs *storage.BucketAttrs
	err := timeGCSCall(r.Context(), "GetBucketLifecycle", func(ctx context.Context) error {
		var e error
		attrs, e = bucket.Attrs(ctx)
		return e
	})
	if err != nil {
		slog.Error("GCS API call failed for GetBucketLifecycle", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to retrieve lifecycle configuration from GCS.")
		return
	}

	s3Cfg := translate.TranslateGCSToS3Lifecycle(attrs.Lifecycle)
	if s3Cfg == nil || len(s3Cfg.Rules) == 0 {
		writeS3Error(w, http.StatusNotFound, "NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist.")
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(s3Cfg)
}

func handleDeleteLifecycle(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())
	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}
	if config.Config.DryRun {
		log.Info("[DRY_RUN] Would delete lifecycle configuration", "bucket", targetBucket)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	bucket := gcsClient.Bucket(targetBucket)
	uattrs := storage.BucketAttrsToUpdate{
		Lifecycle: &storage.Lifecycle{Rules: nil},
	}

	err := timeGCSCall(r.Context(), "DeleteBucketLifecycle", func(ctx context.Context) error {
		_, e := bucket.Update(ctx, uattrs)
		return e
	})
	if err != nil {
		slog.Error("GCS API call failed for DeleteBucketLifecycle", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to delete lifecycle configuration on GCS.")
		return
	}

	log.Info("Successfully deleted GCS bucket lifecycle", "bucket", targetBucket)
	w.WriteHeader(http.StatusNoContent)
}

func handlePutCORS(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())

	var s3Cfg translate.CORSConfiguration
	if !decodeControlPlaneXML(w, r, "cors", &s3Cfg) {
		return
	}

	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}

	// Translate to GCS CORS.
	gcsCORS, droppedHeaders := translate.TranslateS3ToGCSCors(&s3Cfg)

	// Warn client about unsupported AllowedHeaders via response header
	if len(droppedHeaders) > 0 {
		w.Header().Set("X-S3Proxy-Warning",
			fmt.Sprintf("AllowedHeaders not supported by GCS and were ignored: %s", strings.Join(droppedHeaders, ", ")))
	}

	// 4. In DryRun mode, just print/return success
	if config.Config.DryRun {
		w.WriteHeader(http.StatusOK)

		return
	}

	// 5. Execute Bucket Update via GCS SDK
	bucket := gcsClient.Bucket(targetBucket)
	uattrs := storage.BucketAttrsToUpdate{
		CORS: gcsCORS,
	}

	err := timeGCSCall(r.Context(), "PutBucketCors", func(ctx context.Context) error {
		_, e := bucket.Update(ctx, uattrs)
		return e
	})
	if err != nil {
		log.Error("GCS API call failed for PutBucketCors", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to update CORS configuration on GCS.")
		return
	}

	log.Info("Successfully updated GCS bucket CORS", "bucket", targetBucket)
	w.WriteHeader(http.StatusOK)
}

func handleGetCORS(w http.ResponseWriter, r *http.Request) {
	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}
	if config.Config.DryRun {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		xml.NewEncoder(w).Encode(&translate.CORSConfiguration{})
		return
	}
	bucket := gcsClient.Bucket(targetBucket)
	var attrs *storage.BucketAttrs
	err := timeGCSCall(r.Context(), "GetBucketCors", func(ctx context.Context) error {
		var e error
		attrs, e = bucket.Attrs(ctx)
		return e
	})
	if err != nil {
		slog.Error("GCS API call failed for GetBucketCors", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to retrieve CORS configuration from GCS.")
		return
	}

	s3Cfg := translate.TranslateGCSToS3Cors(attrs.CORS)
	if s3Cfg == nil {
		s3Cfg = &translate.CORSConfiguration{} // Return empty but valid XML
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(s3Cfg)
}

func handleDeleteCORS(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())
	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}
	if config.Config.DryRun {
		log.Info("[DRY_RUN] Would delete CORS configuration", "bucket", targetBucket)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	bucket := gcsClient.Bucket(targetBucket)
	uattrs := storage.BucketAttrsToUpdate{
		CORS: []storage.CORS{},
	}

	err := timeGCSCall(r.Context(), "DeleteBucketCors", func(ctx context.Context) error {
		_, e := bucket.Update(ctx, uattrs)
		return e
	})
	if err != nil {
		slog.Error("GCS API call failed for DeleteBucketCors", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to delete CORS configuration on GCS.")
		return
	}

	log.Info("Successfully deleted GCS bucket CORS", "bucket", targetBucket)
	w.WriteHeader(http.StatusNoContent)
}

func handlePutLogging(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())

	var s3Cfg translate.BucketLoggingStatus
	if !decodeControlPlaneXML(w, r, "logging", &s3Cfg) {
		return
	}

	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}

	gcsLogging := translate.TranslateS3ToGCSLogging(s3Cfg)

	if config.Config.DryRun {
		w.WriteHeader(http.StatusOK)

		return
	}

	bucket := gcsClient.Bucket(targetBucket)
	uattrs := storage.BucketAttrsToUpdate{
		Logging: gcsLogging,
	}

	err := timeGCSCall(r.Context(), "PutBucketLogging", func(ctx context.Context) error {
		_, e := bucket.Update(ctx, uattrs)
		return e
	})
	if err != nil {
		log.Error("GCS API call failed for PutBucketLogging", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to update logging configuration on GCS.")
		return
	}

	log.Info("Successfully updated GCS bucket Logging", "bucket", targetBucket)
	w.WriteHeader(http.StatusOK)
}

func handleGetLogging(w http.ResponseWriter, r *http.Request) {
	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}
	if config.Config.DryRun {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		xml.NewEncoder(w).Encode(&translate.BucketLoggingStatus{})
		return
	}
	bucket := gcsClient.Bucket(targetBucket)
	var attrs *storage.BucketAttrs
	err := timeGCSCall(r.Context(), "GetBucketLogging", func(ctx context.Context) error {
		var e error
		attrs, e = bucket.Attrs(ctx)
		return e
	})
	if err != nil {
		slog.Error("GCS API call failed for GetBucketLogging", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to retrieve logging configuration from GCS.")
		return
	}

	s3Cfg := translate.TranslateGCSToS3Logging(attrs.Logging)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(s3Cfg)
}

func handleDeleteLogging(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())
	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}
	if config.Config.DryRun {
		log.Info("[DRY_RUN] Would delete logging configuration", "bucket", targetBucket)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	bucket := gcsClient.Bucket(targetBucket)
	uattrs := storage.BucketAttrsToUpdate{
		Logging: &storage.BucketLogging{},
	}

	err := timeGCSCall(r.Context(), "DeleteBucketLogging", func(ctx context.Context) error {
		_, e := bucket.Update(ctx, uattrs)
		return e
	})
	if err != nil {
		slog.Error("GCS API call failed for DeleteBucketLogging", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to delete logging configuration on GCS.")
		return
	}

	log.Info("Successfully deleted GCS bucket Logging", "bucket", targetBucket)
	w.WriteHeader(http.StatusNoContent)
}

func handlePutWebsite(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())

	var s3Cfg translate.WebsiteConfiguration
	if !decodeControlPlaneXML(w, r, "website", &s3Cfg) {
		return
	}

	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}

	gcsWebsite := translate.TranslateS3ToGCSWebsite(s3Cfg)

	if config.Config.DryRun {
		w.WriteHeader(http.StatusOK)

		return
	}

	bucket := gcsClient.Bucket(targetBucket)
	uattrs := storage.BucketAttrsToUpdate{
		Website: gcsWebsite,
	}

	err := timeGCSCall(r.Context(), "PutBucketWebsite", func(ctx context.Context) error {
		_, e := bucket.Update(ctx, uattrs)
		return e
	})
	if err != nil {
		log.Error("GCS API call failed for PutBucketWebsite", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to update website configuration on GCS.")
		return
	}

	log.Info("Successfully updated GCS bucket Website", "bucket", targetBucket)
	w.WriteHeader(http.StatusOK)
}

func handleGetWebsite(w http.ResponseWriter, r *http.Request) {
	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}
	if config.Config.DryRun {
		writeS3Error(w, http.StatusNotFound, "NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration.")
		return
	}
	bucket := gcsClient.Bucket(targetBucket)
	var attrs *storage.BucketAttrs
	err := timeGCSCall(r.Context(), "GetBucketWebsite", func(ctx context.Context) error {
		var e error
		attrs, e = bucket.Attrs(ctx)
		return e
	})
	if err != nil {
		slog.Error("GCS API call failed for GetBucketWebsite", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to retrieve website configuration from GCS.")
		return
	}

	s3Cfg := translate.TranslateGCSToS3Website(attrs.Website)
	if s3Cfg == nil {
		writeS3Error(w, http.StatusNotFound, "NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration.")
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(s3Cfg)
}

func handleDeleteWebsite(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())
	targetBucket, ok := parseBucketFromPath(w, r)
	if !ok {
		return
	}
	if config.Config.DryRun {
		log.Info("[DRY_RUN] Would delete website configuration", "bucket", targetBucket)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	bucket := gcsClient.Bucket(targetBucket)
	uattrs := storage.BucketAttrsToUpdate{
		Website: &storage.BucketWebsite{},
	}

	err := timeGCSCall(r.Context(), "DeleteBucketWebsite", func(ctx context.Context) error {
		_, e := bucket.Update(ctx, uattrs)
		return e
	})
	if err != nil {
		log.Error("GCS API call failed for DeleteBucketWebsite", "error", err, "bucket", targetBucket)
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Failed to delete website configuration on GCS.")
		return
	}

	log.Info("Successfully deleted GCS bucket Website", "bucket", targetBucket)
	w.WriteHeader(http.StatusNoContent)
}

func handlePutObjectTagging(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())

	var s3Cfg translate.Tagging
	if !decodeControlPlaneXML(w, r, "tagging", &s3Cfg) {
		return
	}

	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[0] == "" || pathParts[1] == "" {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Bucket and Object name required.")
		return
	}
	targetBucket := pathParts[0]
	targetObject := strings.Join(pathParts[1:], "/")

	log.Info("Applying Tagging to GCS Object", "bucket", targetBucket, "object", targetObject)

	if config.Config.DryRun {
		log.Info("[DRY_RUN] Would apply Tagging to GCS Object", "bucket", targetBucket, "object", targetObject)
		w.WriteHeader(http.StatusOK)

		return
	}

	obj := gcsClient.Bucket(targetBucket).Object(targetObject)
	var attrs *storage.ObjectAttrs
	err := timeGCSCall(r.Context(), "GetObjectAttrs_Tagging", func(ctx context.Context) error {
		var e error
		attrs, e = obj.Attrs(ctx)
		return e
	})
	if err != nil {
		log.Error("GCS API call failed for GetObjectAttrs_Tagging", "error", err)
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}

	newContexts := translate.TranslateS3ToGCSContexts(s3Cfg, attrs.Contexts)
	uattrs := storage.ObjectAttrsToUpdate{
		Contexts: newContexts,
	}

	err = timeGCSCall(r.Context(), "PutObjectTagging", func(ctx context.Context) error {
		_, e := obj.If(storage.Conditions{
			MetagenerationMatch: attrs.Metageneration,
		}).Update(ctx, uattrs)
		return e
	})
	if err != nil {
		log.Error("GCS API call failed for PutObjectTagging", "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to update object tagging.")
		return
	}

	log.Info("Successfully updated GCS Object Tagging", "bucket", targetBucket, "object", targetObject)
	w.WriteHeader(http.StatusOK)
}

func handleGetObjectTagging(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[0] == "" || pathParts[1] == "" {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Bucket and Object name required.")
		return
	}
	targetBucket := pathParts[0]
	targetObject := strings.Join(pathParts[1:], "/")

	if config.Config.DryRun {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Tagging><TagSet></TagSet></Tagging>")
		return
	}

	obj := gcsClient.Bucket(targetBucket).Object(targetObject)
	var attrs *storage.ObjectAttrs
	err := timeGCSCall(r.Context(), "GetObjectAttrs_GetTagging", func(ctx context.Context) error {
		var e error
		attrs, e = obj.Attrs(ctx)
		return e
	})
	if err != nil {
		slog.Error("GCS API call failed for GetObjectAttrs_GetTagging", "error", err)
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}

	s3Cfg := translate.TranslateGCSContextsToS3Tagging(attrs.Contexts)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(s3Cfg)
}

func handleDeleteObjectTagging(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())

	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[0] == "" || pathParts[1] == "" {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Bucket and Object name required.")
		return
	}
	targetBucket := pathParts[0]
	targetObject := strings.Join(pathParts[1:], "/")

	if config.Config.DryRun {
		log.Info("[DRY_RUN] Would delete Tagging from GCS Object", "bucket", targetBucket, "object", targetObject)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	obj := gcsClient.Bucket(targetBucket).Object(targetObject)
	var attrs *storage.ObjectAttrs
	err := timeGCSCall(r.Context(), "GetObjectAttrs_DeleteTagging", func(ctx context.Context) error {
		var e error
		attrs, e = obj.Attrs(ctx)
		return e
	})
	if err != nil {
		log.Error("GCS API call failed for GetObjectAttrs_DeleteTagging", "error", err)
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}

	// Clearing all Object Contexts: pass an empty Custom map so the SDK
	// signals "remove every context key" to GCS. A nil Custom would be a
	// no-op per SDK semantics.
	uattrs := storage.ObjectAttrsToUpdate{
		Contexts: &storage.ObjectContexts{Custom: map[string]storage.ObjectCustomContextPayload{}},
	}

	err = timeGCSCall(r.Context(), "DeleteObjectTagging", func(ctx context.Context) error {
		_, e := obj.If(storage.Conditions{
			MetagenerationMatch: attrs.Metageneration,
		}).Update(ctx, uattrs)
		return e
	})
	if err != nil {
		log.Error("GCS API call failed for DeleteObjectTagging", "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to delete object tagging.")
		return
	}

	log.Info("Successfully deleted GCS Object Tagging", "bucket", targetBucket, "object", targetObject)
	w.WriteHeader(http.StatusNoContent)
}

// handleRestoreObject synthesises an S3-compatible response for
// `POST /<bucket>/<key>?restore`. GCS has no concept of "frozen" objects —
// every storage class (STANDARD / NEARLINE / COLDLINE / ARCHIVE) is
// immediately readable — so we return 200 OK as if the object were already
// restored rather than forwarding to GCS (which would reply 400
// InvalidArgument).
//
// Behaviour:
//   - Consume at most maxControlPlaneBodySize of the request body and discard
//     it. AWS callers may send a <RestoreRequest> XML document we do not
//     need to parse; reading it ensures HTTP/1.1 keep-alive and SigV4
//     Content-Length accounting stay healthy.
//   - By default issue a HEAD probe so missing keys surface 404 NoSuchKey,
//     matching AWS semantics. Operators can disable the probe via
//     RESTORE_SKIP_EXISTENCE_CHECK=true when they want zero extra GCS calls.
//   - Respond with an empty body and Content-Length: 0. A Date response
//     header is added for log correlation.
func handleRestoreObject(w http.ResponseWriter, r *http.Request) {
	log := reqLogger(r.Context())

	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[0] == "" || pathParts[1] == "" {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument",
			"Bucket and Object name required for RestoreObject.")
		return
	}
	targetBucket := pathParts[0]
	targetObject := strings.Join(pathParts[1:], "/")

	// Drain the body with the same cap as other control-plane endpoints so
	// an oversized <RestoreRequest> cannot exhaust memory. We never parse
	// the XML; <Days>, GlacierJobParameters, Tier are not meaningful on GCS.
	r.Body = http.MaxBytesReader(w, r.Body, maxControlPlaneBodySize)
	defer r.Body.Close()
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeS3Error(w, http.StatusBadRequest, "MaxMessageLengthExceeded",
				fmt.Sprintf("Your request was too big. Max RestoreObject body size is %d bytes.", maxControlPlaneBodySize))
			return
		}
		log.Warn("Failed to drain RestoreObject body", "error", err)
	}

	// Existence probe: run unless DryRun skips GCS entirely or the operator
	// opted out. Keeping this behind an env flag lets latency-sensitive
	// callers trade strict NoSuchKey behaviour for a zero-GCS fast path.
	if !config.Config.DryRun && !config.Config.RestoreSkipExistenceCheck {
		if gcsClient == nil {
			// Should not happen outside DryRun (startup would have failed),
			// but guard anyway so the shim never panics.
			log.Error("RestoreObject invoked without a GCS client", "bucket", targetBucket, "object", targetObject)
			writeS3Error(w, http.StatusInternalServerError, "InternalError",
				"Proxy misconfiguration: GCS client unavailable.")
			return
		}
		obj := gcsClient.Bucket(targetBucket).Object(targetObject)
		err := timeGCSCall(r.Context(), "RestoreObject_HeadProbe", func(ctx context.Context) error {
			_, e := obj.Attrs(ctx)
			return e
		})
		if err != nil {
			if errors.Is(err, storage.ErrObjectNotExist) {
				writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
				return
			}
			log.Error("GCS API call failed for RestoreObject_HeadProbe", "error", err)
			writeS3Error(w, http.StatusBadGateway, "InternalError",
				"Failed to verify object existence prior to synthesising RestoreObject response.")
			return
		}
	}

	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Length", "0")
	// Status 200 (not 202) because on GCS the object is already "restored" —
	// callers can GET it immediately without polling.
	w.WriteHeader(http.StatusOK)

	log.Info("Synthesised RestoreObject response",
		"bucket", targetBucket,
		"object", targetObject,
		"skip_existence_check", config.Config.RestoreSkipExistenceCheck,
		"dry_run", config.Config.DryRun,
	)
}

// decodeControlPlaneXML reads and unmarshals a size-capped XML body into
// `out`, which MUST be a non-nil pointer to a value compatible with
// encoding/xml.Unmarshal. Returns true on success; otherwise it has
// already written an S3-compatible error response to `w` and the caller
// should return immediately.
//
// Centralises the boilerplate previously duplicated across
// handlePutLifecycle / handlePutCORS / handlePutLogging / handlePutWebsite
// / handlePutObjectTagging — with consistent request-size capping
// (maxControlPlaneBodySize) and MaxBytesError detection via errors.As
// instead of brittle string matching.
func decodeControlPlaneXML(w http.ResponseWriter, r *http.Request, label string, out any) bool {
	log := reqLogger(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, maxControlPlaneBodySize)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeS3Error(w, http.StatusBadRequest, "MaxMessageLengthExceeded",
				fmt.Sprintf("Your request was too big. Max configuration size is %d bytes.", maxControlPlaneBodySize))
			return false
		}
		log.Error("Failed to read control-plane request body", "label", label, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to read request body.")
		return false
	}
	log.Info("Read control-plane request body", "label", label, "body_size", len(body))

	if err := xml.Unmarshal(body, out); err != nil {
		log.Error("Failed to unmarshal S3 XML", "label", label, "error", err)
		writeS3Error(w, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.")
		return false
	}
	return true
}

// s3ErrorBody is the on-the-wire shape of an AWS S3 error response. The XML
// prolog is written separately so we preserve the canonical
// `<?xml version="1.0" encoding="UTF-8"?>` header that S3 SDK parsers expect.
type s3ErrorBody struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

// writeS3Error emits a standard AWS S3-format XML error response.
//
// The payload is produced with encoding/xml so that special characters in
// `message` (e.g. user-supplied filter names containing `<`, `&`, `"`) are
// safely escaped. Prior to v1.4 this used fmt.Fprintf, which could emit
// invalid XML when an error surfaced attacker-controlled strings.
func writeS3Error(w http.ResponseWriter, statusCode int, code string, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)
	fmt.Fprint(w, xml.Header)
	enc := xml.NewEncoder(w)
	if err := enc.Encode(s3ErrorBody{Code: code, Message: message}); err != nil {
		slog.Error("Failed to encode S3 error body", "error", err)
	}
	_ = enc.Flush()
	fmt.Fprintln(w)
}
