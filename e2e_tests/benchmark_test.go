package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ---------------------------------------------------------------------------
// Configuration (overridable via environment variables)
// ---------------------------------------------------------------------------

func getBenchConcurrency() int {
	if v := os.Getenv("BENCH_CONCURRENCY"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			return n
		}
	}
	return 20
}

func getBenchDurationSec() int {
	if v := os.Getenv("BENCH_DURATION_SEC"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			return n
		}
	}
	return 30
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

// BenchmarkReport holds the aggregate benchmark results with system metrics.
type BenchmarkReport struct {
	Timestamp     string            `json:"timestamp"`
	ProxyEndpoint string            `json:"proxy_endpoint"`
	Config        BenchmarkConfig   `json:"config"`
	Results       []BenchmarkResult `json:"results"`
}

type BenchmarkConfig struct {
	Concurrency int `json:"concurrency"`
	DurationSec int `json:"duration_sec"`
}

// BenchmarkResult holds a single benchmark's statistics.
type BenchmarkResult struct {
	Name        string       `json:"name"`
	PayloadSize string       `json:"payload_size"`
	Concurrency int          `json:"concurrency"`
	DurationSec float64      `json:"duration_sec"`
	TotalOps    int64        `json:"total_ops"`
	Errors      int64        `json:"errors"`
	OpsPerSec   float64      `json:"ops_per_sec"`
	P50Ms       float64      `json:"p50_ms"`
	P95Ms       float64      `json:"p95_ms"`
	P99Ms       float64      `json:"p99_ms"`
	AvgMs       float64      `json:"avg_ms"`
	MaxMs       float64      `json:"max_ms"`
	System      SystemDelta  `json:"system_metrics"`
	Network     NetworkStats `json:"network_stats"`
}

// ---------------------------------------------------------------------------
// Latency helpers
// ---------------------------------------------------------------------------

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)) * p)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func avgDuration(sorted []time.Duration) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	return total / time.Duration(len(sorted))
}

func durationMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

// ---------------------------------------------------------------------------
// Concurrent load runner
// ---------------------------------------------------------------------------

// loadResult holds raw results from a concurrent load test.
type loadResult struct {
	latencies []time.Duration
	totalOps  int64
	errors    int64
}

// runConcurrentLoad runs fn across N goroutines for the specified duration,
// collecting per-operation latencies from all goroutines.
func runConcurrentLoad(concurrency int, duration time.Duration, fn func() error) loadResult {
	var (
		mu        sync.Mutex
		allLats   []time.Duration
		totalOps  atomic.Int64
		totalErrs atomic.Int64
	)

	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup

	for g := 0; g < concurrency; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var localLats []time.Duration

			for time.Now().Before(deadline) {
				start := time.Now()
				if err := fn(); err != nil {
					totalErrs.Add(1)
				} else {
					localLats = append(localLats, time.Since(start))
				}
				totalOps.Add(1)
			}

			mu.Lock()
			allLats = append(allLats, localLats...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	sort.Slice(allLats, func(i, j int) bool { return allLats[i] < allLats[j] })

	return loadResult{
		latencies: allLats,
		totalOps:  totalOps.Load(),
		errors:    totalErrs.Load(),
	}
}

// toBenchmarkResult constructs a BenchmarkResult from load results + system delta + network stats.
func toBenchmarkResult(name, payloadSize string, concurrency int, lr loadResult, wallClock time.Duration, delta SystemDelta, netStats NetworkStats) BenchmarkResult {
	opsPerSec := 0.0
	if wallClock.Seconds() > 0 {
		opsPerSec = float64(len(lr.latencies)) / wallClock.Seconds()
	}

	maxMs := 0.0
	if len(lr.latencies) > 0 {
		maxMs = durationMs(lr.latencies[len(lr.latencies)-1])
	}

	return BenchmarkResult{
		Name:        name,
		PayloadSize: payloadSize,
		Concurrency: concurrency,
		DurationSec: wallClock.Seconds(),
		TotalOps:    lr.totalOps,
		Errors:      lr.errors,
		OpsPerSec:   opsPerSec,
		P50Ms:       durationMs(percentile(lr.latencies, 0.50)),
		P95Ms:       durationMs(percentile(lr.latencies, 0.95)),
		P99Ms:       durationMs(percentile(lr.latencies, 0.99)),
		AvgMs:       durationMs(avgDuration(lr.latencies)),
		MaxMs:       maxMs,
		System:      delta,
		Network:     netStats,
	}
}

// ---------------------------------------------------------------------------
// Payload helpers
// ---------------------------------------------------------------------------

type payloadTier struct {
	Name string
	Size int
}

var payloadTiers = []payloadTier{
	{"1KB", 1024},
	{"100KB", 100 * 1024},
	{"1MB", 1024 * 1024},
	{"10MB", 10 * 1024 * 1024},
}

func makePayload(size int) string {
	return strings.Repeat("X", size)
}

// ---------------------------------------------------------------------------
// Benchmark suite
// ---------------------------------------------------------------------------

// TestBenchmarkSuite runs all benchmarks with concurrent load and system metrics.
func TestBenchmarkSuite(t *testing.T) {
	client := NewS3Client(t, testEnv)
	bucket := testEnv.TestBucket
	concurrency := getBenchConcurrency()
	durationSec := getBenchDurationSec()
	duration := time.Duration(durationSec) * time.Second

	mc := NewMetricsCollector(testEnv.ProxyEndpoint)

	report := BenchmarkReport{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		ProxyEndpoint: testEnv.ProxyEndpoint,
		Config: BenchmarkConfig{
			Concurrency: concurrency,
			DurationSec: durationSec,
		},
	}

	t.Logf("Benchmark config: concurrency=%d, duration=%ds", concurrency, durationSec)
	t.Log("")

	// =======================================================================
	// 1. Multi-tier PutObject load test
	// =======================================================================
	for _, tier := range payloadTiers {
		t.Logf("=== PutObject %s (%d concurrent, %ds) ===", tier.Name, concurrency, durationSec)
		payload := makePayload(tier.Size)

		before, _ := mc.Snapshot()
		start := time.Now()
		ns := NewNetworkSampler(time.Second)
		ns.Start()

		lr := runConcurrentLoad(concurrency, duration, func() error {
			key := fmt.Sprintf("%sbench-put-%s-%d", testEnv.TestPrefix, tier.Name, time.Now().UnixNano())
			_, err := client.PutObject(context.TODO(), &s3.PutObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
				Body:   strings.NewReader(payload),
			})
			// Best-effort cleanup (fire and forget)
			if err == nil {
				go func() {
					client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
						Bucket: aws.String(bucket),
						Key:    aws.String(key),
					})
				}()
			}
			return err
		})

		netStats := ns.Stop()
		wallClock := time.Since(start)
		after, _ := mc.Snapshot()
		delta := ComputeDelta(before, after, wallClock)

		result := toBenchmarkResult("PutObject_"+tier.Name, tier.Name, concurrency, lr, wallClock, delta, netStats)
		report.Results = append(report.Results, result)

		printBenchResult(t, result)
	}

	// =======================================================================
	// 2. Multi-tier GetObject load test
	// =======================================================================
	for _, tier := range payloadTiers {
		t.Logf("=== GetObject %s (%d concurrent, %ds) ===", tier.Name, concurrency, durationSec)

		// Seed one object for reads
		seedKey := fmt.Sprintf("%sbench-get-seed-%s", testEnv.TestPrefix, tier.Name)
		payload := makePayload(tier.Size)
		_, err := client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(seedKey),
			Body:   strings.NewReader(payload),
		})
		if err != nil {
			t.Logf("  [skip] Failed to seed object for GetObject %s: %v", tier.Name, err)
			continue
		}
		t.Cleanup(func() { Cleanup(t, client, bucket, seedKey) })

		before, _ := mc.Snapshot()
		start := time.Now()
		ns := NewNetworkSampler(time.Second)
		ns.Start()

		lr := runConcurrentLoad(concurrency, duration, func() error {
			out, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(seedKey),
			})
			if err != nil {
				return err
			}
			io.Copy(io.Discard, out.Body)
			out.Body.Close()
			return nil
		})

		netStats := ns.Stop()
		wallClock := time.Since(start)
		after, _ := mc.Snapshot()
		delta := ComputeDelta(before, after, wallClock)

		result := toBenchmarkResult("GetObject_"+tier.Name, tier.Name, concurrency, lr, wallClock, delta, netStats)
		report.Results = append(report.Results, result)

		printBenchResult(t, result)
	}

	// =======================================================================
	// 3. Full CRUD cycle load test (1KB)
	// =======================================================================
	t.Logf("=== PutGetDelete CRUD Cycle (%d concurrent, %ds) ===", concurrency, durationSec)

	before, _ := mc.Snapshot()
	start := time.Now()
	nsCRUD := NewNetworkSampler(time.Second)
	nsCRUD.Start()

	crudLR := runConcurrentLoad(concurrency, duration, func() error {
		key := fmt.Sprintf("%sbench-crud-%d", testEnv.TestPrefix, time.Now().UnixNano())
		// Put
		_, err := client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			Body:   strings.NewReader(strings.Repeat("Y", 1024)),
		})
		if err != nil {
			return err
		}
		// Get
		out, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return err
		}
		io.Copy(io.Discard, out.Body)
		out.Body.Close()
		// Delete
		_, err = client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		return err
	})

	netStatsCRUD := nsCRUD.Stop()
	wallClock := time.Since(start)
	after, _ := mc.Snapshot()
	delta := ComputeDelta(before, after, wallClock)

	crudResult := toBenchmarkResult("PutGetDelete_CRUD", "1KB", concurrency, crudLR, wallClock, delta, netStatsCRUD)
	report.Results = append(report.Results, crudResult)
	printBenchResult(t, crudResult)

	// =======================================================================
	// 4. Control Plane: PutBucketLifecycle load test
	// GCS enforces ~1 QPS per bucket for metadata writes (bucket.Update).
	// Running more than 1 concurrent goroutine against the same bucket will
	// immediately saturate the GCS rate limit and produce 502 errors.
	// We therefore cap concurrency at 1 for all control-plane scenarios.
	// =======================================================================
	lcConcurrency := 1
	t.Logf("=== PutBucketLifecycle (%d concurrent [GCS metadata write limit], %ds) ===", lcConcurrency, durationSec)
	t.Cleanup(func() {
		client.DeleteBucketLifecycle(context.TODO(), &s3.DeleteBucketLifecycleInput{
			Bucket: aws.String(bucket),
		})
	})

	before, _ = mc.Snapshot()
	start = time.Now()
	nsLC := NewNetworkSampler(time.Second)
	nsLC.Start()

	lcLR := runConcurrentLoad(lcConcurrency, duration, func() error {
		_, err := client.PutBucketLifecycleConfiguration(context.TODO(), &s3.PutBucketLifecycleConfigurationInput{
			Bucket: aws.String(bucket),
			LifecycleConfiguration: &types.BucketLifecycleConfiguration{
				Rules: []types.LifecycleRule{
					{
						ID:     aws.String("bench-rule"),
						Status: types.ExpirationStatusEnabled,
						Filter: &types.LifecycleRuleFilter{Prefix: aws.String("bench/")},
						Expiration: &types.LifecycleExpiration{
							Days: aws.Int32(90),
						},
					},
				},
			},
		})
		return err
	})

	netStatsLC := nsLC.Stop()
	wallClock = time.Since(start)
	after, _ = mc.Snapshot()
	delta = ComputeDelta(before, after, wallClock)

	lcResult := toBenchmarkResult("PutBucketLifecycle", "N/A", lcConcurrency, lcLR, wallClock, delta, netStatsLC)
	report.Results = append(report.Results, lcResult)
	printBenchResult(t, lcResult)

	// =======================================================================
	// 5. Write JSON report
	// =======================================================================
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal benchmark report: %v", err)
	}

	reportPath := "benchmark_report.json"
	if err := os.WriteFile(reportPath, reportJSON, 0644); err != nil {
		t.Logf("Warning: failed to write report to %s: %v", reportPath, err)
	} else {
		t.Logf("Benchmark report written to %s", reportPath)
	}

	// Also emit JSON to stdout with markers for easy extraction from container logs
	fmt.Println("BENCHMARK_JSON_START")
	fmt.Println(string(reportJSON))
	fmt.Println("BENCHMARK_JSON_END")

	// Print final summary table
	fmt.Println()
	fmt.Println("================================================================================")
	fmt.Println("  Benchmark Summary")
	fmt.Printf("  Concurrency: %d | Duration per test: %ds\n", concurrency, durationSec)
	fmt.Println("================================================================================")
	fmt.Printf("  %-25s %6s %6s %8s %8s %8s %8s %8s %6s\n",
		"Name", "Size", "Ops", "ops/s", "p50(ms)", "p95(ms)", "p99(ms)", "max(ms)", "Errs")
	fmt.Println("  " + strings.Repeat("-", 94))
	for _, r := range report.Results {
		fmt.Printf("  %-25s %6s %6d %8.1f %8.1f %8.1f %8.1f %8.1f %6d\n",
			r.Name, r.PayloadSize, r.TotalOps, r.OpsPerSec, r.P50Ms, r.P95Ms, r.P99Ms, r.MaxMs, r.Errors)
	}
	fmt.Println("================================================================================")
	fmt.Println()

	// Print system metrics summary
	fmt.Println("  System Metrics (per benchmark):")
	fmt.Printf("  %-25s %8s %10s %10s %10s %10s\n",
		"Name", "CPU(%)", "Mem\u0394(MB)", "PeakMem", "Gortn\u0394", "HTTP\u0394")
	fmt.Println("  " + strings.Repeat("-", 78))
	for _, r := range report.Results {
		fmt.Printf("  %-25s %8.1f %10.1f %10.1f %10.0f %10.0f\n",
			r.Name, r.System.CPUUsagePercent, r.System.MemoryDeltaMB,
			r.System.PeakResidentMB, r.System.GoroutineDelta, r.System.HTTPRequestsDelta)
	}
	fmt.Println("================================================================================")
	fmt.Println()

	// Print network throughput summary
	fmt.Println("  Network Throughput (benchmark pod, MB/s):")
	fmt.Printf("  %-25s %10s %10s %10s %10s %10s %10s\n",
		"Name", "Rx avg", "Rx max", "Rx min", "Tx avg", "Tx max", "Tx min")
	fmt.Println("  " + strings.Repeat("-", 90))
	for _, r := range report.Results {
		fmt.Printf("  %-25s %10.2f %10.2f %10.2f %10.2f %10.2f %10.2f\n",
			r.Name,
			r.Network.AvgRxMBps, r.Network.MaxRxMBps, r.Network.MinRxMBps,
			r.Network.AvgTxMBps, r.Network.MaxTxMBps, r.Network.MinTxMBps)
	}
	fmt.Println("================================================================================")
}

func printBenchResult(t *testing.T, r BenchmarkResult) {
	t.Logf("  ops=%d  ops/s=%.1f  p50=%.1fms  p95=%.1fms  p99=%.1fms  max=%.1fms  errors=%d",
		r.TotalOps, r.OpsPerSec, r.P50Ms, r.P95Ms, r.P99Ms, r.MaxMs, r.Errors)
	t.Logf("  [system] CPU=%.1f%%  Mem\u0394=%.1fMB  PeakMem=%.1fMB  Goroutine\u0394=%.0f  HTTP\u0394=%.0f",
		r.System.CPUUsagePercent, r.System.MemoryDeltaMB,
		r.System.PeakResidentMB, r.System.GoroutineDelta, r.System.HTTPRequestsDelta)
	t.Logf("  [network] Rx avg=%.2f max=%.2f min=%.2f MB/s | Tx avg=%.2f max=%.2f min=%.2f MB/s (samples=%d)",
		r.Network.AvgRxMBps, r.Network.MaxRxMBps, r.Network.MinRxMBps,
		r.Network.AvgTxMBps, r.Network.MaxTxMBps, r.Network.MinTxMBps, r.Network.Samples)
	t.Log("")
}
