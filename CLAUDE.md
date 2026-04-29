# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

S3Proxy4GCS is a Go middleware proxy that translates AWS S3 API requests to Google Cloud Storage (GCS). It intercepts S3 requests, translates unsupported features via GCS native APIs, re-signs with HMAC credentials, and forwards to GCS's S3-compatible endpoint.

## Build & Run

```bash
go run .                      # Run locally (DRY_RUN=true by default)
go build -o s3proxy .         # Build binary
docker build -t s3proxy .     # Build container (multi-stage: Alpine builder + distroless runtime)
```

## Testing

The project has three separate Go modules for tests, each in its own directory:

```bash
# Integration tests (local, uses DryRun mode, no live GCS needed)
cd integration_tests && go test -v ./...

# Run a single integration test
cd integration_tests && go test -v -run TestLifecyclePut ./...

# E2E tests (requires live proxy + env vars: PROXY_ENDPOINT, GCS_HMAC_ACCESS, GCS_HMAC_SECRET, TEST_BUCKET)
cd e2e_tests && go test -v -count=1 -timeout 30m ./...

# Translation unit tests (in main module)
go test -v ./pkg/translate/...
```

Integration and E2E tests are **isolated Go modules** with their own `go.mod` — run `go test` from within their directories.

## Architecture

**Single-binary proxy** with everything in `main.go` (~1250 lines):

- **Chi router** dispatches requests by query parameter (`?lifecycle`, `?cors`, `?logging`, `?website`, `?tagging`) to control-plane handlers, everything else falls through to the reverse proxy
- **Dual reverse proxy**: `readProxy` (GET/HEAD, streaming with `FlushInterval=-1`) and `writeProxy` (PUT/POST/DELETE) with separate transport tuning
- **Director function**: Converts virtual-hosted style to path-style, maps S3 storage classes to GCS equivalents, strips S3-specific headers, re-signs with SigV4
- **Control-plane handlers**: Intercept bucket config operations, translate S3 XML to GCS JSON via `pkg/translate/`, call GCS SDK directly

**Key packages:**
- `config/` — Centralized env var loading (`config.Config` global). All settings in `config/settings.go`.
- `pkg/translate/` — S3 XML struct definitions (`s3_*.go`) and GCS SDK translation functions (`gcs_*.go`) for lifecycle, CORS, logging, website, and tagging

## Engineering Conventions (from AGENTS.md)

- **Config**: All env vars managed in `config/settings.go`. Use `.env` for local dev.
- **Error responses**: Use `writeS3Error()` helper for standard S3 XML errors. Never use plain `http.Error`.
- **Logging**: Use `log/slog` with structured JSON (`slog.Info("msg", "key", val)`), not `log.Printf`.
- **Context propagation**: Always pass `r.Context()` to GCS SDK calls so client aborts cancel outbound calls.
- **Data-plane streaming**: Never buffer full request/response bodies. The reverse proxy streams directly.
- **Lifecycle safety**: Reject lifecycle rules with unsupported filters (Size, Tags) to prevent scope broadening in GCS.
- **K8s QoS**: All deployments must set `requests == limits` (Guaranteed QoS). Use pod anti-affinity between proxy and client pods.

## Key Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `DRY_RUN` | `true` | Disables real GCS hits (safe for local dev) |
| `TARGET_BUCKET` | — | Required when `DRY_RUN=false` |
| `GCP_PROJECT_ID` | — | GCP project for GCS SDK calls |
| `PROXY_AWS_ACCESS_KEY_ID` | — | GCS HMAC access key for re-signing |
| `PROXY_AWS_SECRET_ACCESS_KEY` | — | GCS HMAC secret for re-signing |
| `PROXY_BASE_DOMAIN` | — | Base domain for virtual-hosted style (e.g., `s3proxy.example.com`) |
| `JSON_KEY` | — | Path to GCS Service Account JSON key |
| `PORT` | `8080` | Listen port |
| `DEBUG_LOGGING` | `false` | Verbose JSON logging |

## Operational Endpoints

- `/health` — Liveness probe
- `/readyz` — Readiness probe (tests GCS connectivity)
- `/metrics` — Prometheus metrics
