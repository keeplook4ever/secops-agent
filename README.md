# SecOps Buddy Agent

AI-powered security log analysis and SOC 2 compliance automation for WATI's multi-tenant platform.

## Architecture

```
secops-agent/
├── cmd/agent/main.go              Entry point — analyze | serve subcommands
├── internal/
│   ├── config/config.go           Environment-based configuration
│   ├── ingestion/
│   │   ├── reader.go              JSON log file parser
│   │   └── classifier.go          TENANT vs PLATFORM scope classification
│   ├── sanitizer/
│   │   ├── sanitizer.go           Sanitizer interface + DefaultSanitizer
│   │   ├── pii.go                 IP / email / token / DB name redaction
│   │   └── injection.go           Prompt-injection pattern detection
│   ├── llm/
│   │   ├── client.go              LLM provider interface (swap without changing pipeline)
│   │   ├── anthropic.go           Anthropic Claude implementation (retries, backoff)
│   │   └── prompt.go              System prompt + user message builder
│   ├── analyzer/
│   │   └── analyzer.go            Central pipeline coordinator
│   ├── validator/
│   │   └── validator.go           LLM output schema / CVE / confidence validation
│   ├── reporter/
│   │   ├── json_reporter.go       Structured JSON incident report + per-tenant output
│   │   └── markdown_reporter.go   Human-readable Markdown summary + per-tenant output
│   └── server/
│       ├── server.go              HTTP report server entry point
│       ├── auth.go                JWT HS256 parsing + RBAC middleware
│       ├── handlers.go            Report query handlers with role-based filtering
│       ├── context.go             Request-scoped claims context
│       └── audit.go               Append-only access audit log (JSON Lines)
└── pkg/models/
    ├── log.go                     RawLog / ClassifiedLog types
    ├── sanitized.go               SanitizedLog / SanitizedBatch types
    └── incident.go                LLMFinding / IncidentReport types
```

### Pipeline Flow

```
JSON Log File
    │
    ▼  ingestion.Reader
[RawLog × N]
    │
    ▼  ingestion.Classifier   (logName → TENANT | PLATFORM scope)
[ClassifiedLog × N]
    │
    ▼  sanitizer.DefaultSanitizer
       • PII redaction (IP → REDACTED_IP, email → REDACTED_EMAIL, etc.)
       • Prompt-injection detection on free-text fields
       • tenant_id → TENANT_ID_N deterministic mapping (in-memory only)
[SanitizedLog × N]
    │
    ▼  GroupIntoBatches()     (one LLM call per tenant, never mixed)
[SanitizedBatch per tenant]
    │
    ▼  llm.AnthropicClient.Analyze()
       • System prompt: all instructions — no instructions in user role
       • User message: <log_data>…</log_data> XML delimiter
[raw LLM JSON]
    │
    ▼  validator.Validator
       • JSON schema check + batch completeness
       • Severity enum validation
       • CVE format validation (strips malformed CVE identifiers)
       • Confidence score threshold check
[AnalyzedBatch × N]
    │
    ▼  reporter
       • Global: incident_report.json + incident_summary.md
       • Per-tenant: output/tenants/<tenant_id>/...
       • Platform: output/platform/...
```

## Prerequisites

- Go 1.21+
- An Anthropic API key (or adapt `AnthropicClient` to use another provider)

## Setup

```bash
cd secops-agent
go build ./...        # verify it compiles
```

## Mode 1: Local Startup and Test Guide (Analyze mode)

Run the LLM analysis pipeline and generate reports locally:

```bash
export SECOPS_LLM_API_KEY="your-anthropic-api-key"
export SECOPS_LOG_FILE="./sample-log/Attachment_sample-logs-50.json" 
export SECOPS_LLM_MODEL="claude-sonnet-4-6"

# Optional overrides:
# export SECOPS_OUTPUT_DIR="./output"
# export SECOPS_CONFIDENCE_THRESHOLD="0.7"
# export SECOPS_INCLUDE_INFO="true"

go run ./cmd/agent/ analyze
# or (default mode):
go run ./cmd/agent/
```

Output directory structure (DESIGN.md Q1-Step4):
```
output/
├── incident_report.json         ← Global report (all tenants, for secops-admin)
├── incident_summary.md          ← Global human-readable summary
├── tenants/
│   ├── 600647/
│   │   ├── incident_report.json ← Only this tenant's findings
│   │   └── incident_summary.md
│   ├── 701234/
│   │   └── ...
│   └── ...
└── platform/
    ├── incident_report.json     ← PLATFORM-scoped findings only
    └── incident_summary.md
```

Quick local checks after analyze:

```bash
# 1) Ensure global report exists
ls output/incident_report.json output/incident_summary.md

# 2) Ensure per-tenant and platform outputs exist
ls output/tenants
ls output/platform

# 3) Optional: inspect summary counts
rg "\"critical_count\"|\"high_count\"|\"medium_count\"|\"low_count\"|\"info_count\"" output/incident_report.json
```

## Mode 2: Local Startup and Test Guide (serve mode)

Start an HTTP report server with JWT-based RBAC access control (DESIGN.md Q3):

```bash
export SECOPS_JWT_SECRET="your-secret-key"
export SECOPS_OUTPUT_DIR="./output"
# export SECOPS_SERVER_PORT="8080"  # default

go run ./cmd/agent/ serve
```

#### 1) Generate reports first (required)

The `serve` API reads from `SECOPS_OUTPUT_DIR`, so run analysis once before starting the server:

```bash
export SECOPS_LLM_API_KEY="your-anthropic-api-key"
export SECOPS_LOG_FILE="./sample-log/Attachment_sample-logs-50.json"
go run ./cmd/agent/ analyze
```

#### 2) Start the report server locally

```bash
export SECOPS_JWT_SECRET="dev-secret-change-me"
export SECOPS_OUTPUT_DIR="./output"
export SECOPS_SERVER_PORT="8080"

go run ./cmd/agent/ serve
```

Server base URL: `http://localhost:8080`

#### 3) API endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /healthz` | None | Health check |
| `GET /api/v1/reports` | JWT | List all reports (filtered by role) |
| `GET /api/v1/reports/{tenant_id}` | JWT | Get a specific tenant's report |

#### 4) RBAC roles

| Role | Access Scope |
|------|-------------|
| `secops-admin` | All reports (tenant + platform) |
| `tenant-admin` | Own tenant only (by `tenant_id` claim) |
| `compliance-auditor` | All reports, PII double-redacted |
| `engineer-readonly` | Platform + de-identified tenant reports |

#### 5) JWT format (HS256)

JWT must use HS256 signing with `SECOPS_JWT_SECRET`. Claims:

```json
{
  "sub": "user@example.com",
  "role": "tenant-admin",
  "tenant_id": "600647",
  "exp": 1711540800
}
```

#### 6) Quick health check (no auth)

```bash
curl http://localhost:8080/healthz
```

Expected: HTTP 200 with health status.

#### 7) Create local test JWTs (HS256)

Use [jwt.io](https://jwt.io/) or any HS256 tool with `SECOPS_JWT_SECRET`.
Recommended payloads for local testing:

- `secops-admin`:
  ```json
  {"sub":"admin@wati.io","role":"secops-admin","exp":9999999999}
  ```
- `tenant-admin` for tenant `600647`:
  ```json
  {"sub":"tenant@acme.com","role":"tenant-admin","tenant_id":"600647","exp":9999999999}
  ```
- `engineer-readonly`:
  ```json
  {"sub":"eng@wati.io","role":"engineer-readonly","exp":9999999999}
  ```

#### 8) Validate RBAC behavior with curl

```bash
# Replace with real signed tokens
SECOPS_ADMIN_TOKEN="<SECOPS_ADMIN_JWT>"
TENANT_600647_TOKEN="<TENANT_600647_JWT>"
ENGINEER_TOKEN="<ENGINEER_READONLY_JWT>"
```

List reports:

```bash
curl -H "Authorization: Bearer $SECOPS_ADMIN_TOKEN" \
  http://localhost:8080/api/v1/reports
```

Tenant-admin accesses own tenant (should pass):

```bash
curl -H "Authorization: Bearer $TENANT_600647_TOKEN" \
  http://localhost:8080/api/v1/reports/600647
```

Tenant-admin accesses another tenant (should be denied):

```bash
curl -i -H "Authorization: Bearer $TENANT_600647_TOKEN" \
  http://localhost:8080/api/v1/reports/701234
```

Engineer-readonly checks platform report visibility:

```bash
curl -H "Authorization: Bearer $ENGINEER_TOKEN" \
  http://localhost:8080/api/v1/reports
```

Missing/invalid token check (should be 401):

```bash
curl -i http://localhost:8080/api/v1/reports
```

#### 9) Verify access audit log

After calling the API, confirm audit entries are appended:

```bash
rg "\"path\":\"/api/v1/reports" output/audit.log
```

You should see one JSON line per request with role, subject, tenant_id (if present), path, method, and status.

Audit log format (JSON Lines, append-only):
```json
{"ts":"2026-03-27T12:00:00Z","role":"tenant-admin","sub":"ops@acme.com","tenant_id":"600647","path":"/api/v1/reports/600647","method":"GET","status":200}
```

## Adding a New LLM Provider

1. Create `internal/llm/openai.go` (or `vertex.go`, etc.)
2. Implement `llm.Client`:
   ```go
   type OpenAIClient struct { ... }
   func (c *OpenAIClient) Analyze(ctx context.Context, batch models.SanitizedBatch) ([]byte, error) { ... }
   ```
3. Add a `case "openai":` branch in `cmd/agent/main.go`

No other changes required — the interface boundary ensures the rest of the pipeline is unaffected.

## Security Design

See [DESIGN.md](../DESIGN.md) for the full Part B design document covering:
- Multi-tenant data isolation strategy
- Prompt injection threat model for the LLM pipeline
- Access control model for incident reports

## Key Security Properties

| Property | Implementation |
|----------|---------------|
| PII never reaches LLM | `sanitizer.DefaultSanitizer` runs before any LLM call |
| Tenant data isolation | `GroupIntoBatches()` — one LLM call per tenant, never mixed |
| Per-tenant output storage | `WritePerTenantJSON/MD()` — each tenant gets its own directory |
| Injection neutralised | `injection.go` replaces adversarial fields with `[FLAGGED_INJECTION_ATTEMPT]` |
| LLM output untrusted | `validator.go` validates schema, severity enum, CVE format, confidence score |
| Tenant mapping ephemeral | `tenantMapper` is in-memory only, destroyed after the run |
| Report RBAC enforcement | `server/auth.go` JWT middleware + `handlers.go` role-based filtering |
| Access audit trail | `server/audit.go` append-only JSON Lines log (SOC 2 CC7.2/CC7.3) |

## Scope Note

- CVE handling currently validates identifier format (`CVE-YYYY-NNNN...`) and strips malformed entries. Existence checks against external CVE databases are an optional future extension.
