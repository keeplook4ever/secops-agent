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
│   ├── remediation/
│   │   ├── action.go              ActionType, RiskLevel, ActionSpec, ActionOutcome types
│   │   ├── adapter.go             Port interfaces: RateLimiter, IPBlocker, AccountBanner,
│   │   │                          TenantIsolator, Notifier + AdapterSet bundle
│   │   ├── dispatcher.go          Pure function: (severity, pattern, scope) → []ActionSpec
│   │   ├── engine.go              Engine orchestrator: dedup, dry-run, human gate, execution
│   │   ├── audit.go               RemediationAuditLogger — append-only JSON Lines
│   │   ├── approval.go            PendingApprovalWriter — human-gate queue
│   │   └── adapters/
│   │       ├── noop.go            NoOp stubs (log intent, no real API calls)
│   │       └── http.go            HTTP stub templates (TODO comments, panic until implemented)
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
[IncidentReport]
    │
    ▼  remediation.Engine  (if SECOPS_REMEDIATION_ENABLED=true)
       • Dispatches actions by (severity, attack_pattern, scope)
       • Low-risk: auto-execute via adapters (NoOp by default)
       • High-risk: write to pending_approvals.json + notify IM
       • Every decision written to output/remediation_audit.log
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
export SECOPS_LOG_FILE="../Attachment_sample-logs-50.json"
export SECOPS_LLM_MODEL="claude-sonnet-4-6"

# Optional overrides:
# export SECOPS_OUTPUT_DIR="./output"
# export SECOPS_CONFIDENCE_THRESHOLD="0.7"
# export SECOPS_INCLUDE_INFO="true"

go run ./cmd/agent/ analyze
# or (default mode):
go run ./cmd/agent/
```

Output directory structure:
```
output/
├── incident_report.json          ← Global report (all tenants, for secops-admin)
├── incident_summary.md           ← Global human-readable summary
├── tenants/
│   ├── 600647/
│   │   ├── incident_report.json  ← Only this tenant's findings
│   │   └── incident_summary.md
│   ├── 701234/
│   │   └── ...
│   └── ...
├── platform/
│   ├── incident_report.json      ← PLATFORM-scoped findings only
│   └── incident_summary.md
├── remediation_audit.log         ← Every remediation decision (JSON Lines)
└── pending_approvals.json        ← High-risk actions awaiting human sign-off
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
export SECOPS_LOG_FILE="../Attachment_sample-logs-50.json"
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

## Mode 3: Remediation Engine

The remediation engine is **disabled by default** and runs after report generation. It maps findings to enforcement actions and writes a full audit trail.

### Enable and configure

```bash
# Minimum: enable the engine (dry-run mode by default — no real API calls)
export SECOPS_REMEDIATION_ENABLED=true

# To actually execute actions, disable dry-run:
export SECOPS_REMEDIATION_DRY_RUN=false

# Optional tuning:
export SECOPS_REMEDIATION_MIN_SEVERITY=HIGH   # skip MEDIUM/LOW/INFO
export SECOPS_REMEDIATION_BLOCK_IP_RISK=low   # "low"=auto, "high"=human-gate

# IM notifications (Feishu / Slack) — leave empty to use NoOp logger:
export SECOPS_NOTIFIER_WEBHOOK_URL="https://open.feishu.cn/open-apis/bot/v2/hook/<token>"
export SECOPS_NOTIFIER_APPROVAL_WEBHOOK_URL=""  # falls back to above if unset
```

### Dispatch rules

| Condition | Actions |
|---|---|
| PLATFORM scope (any severity) | `notify` only |
| CRITICAL + BruteForce / CredentialStuffing | `notify`, `rate_limit`, `block_ip` |
| CRITICAL + PromptInjection | `notify`, `rate_limit` |
| CRITICAL + UnauthorizedExec / PrivilegeEscalation / IAMPolicyViolation | `notify`, `isolate_tenant` (human gate) |
| CRITICAL + other patterns | `notify` |
| HIGH + any | `notify`, `rate_limit` |
| MEDIUM / LOW / INFO | No action |

### Two-flag safety model

| `SECOPS_REMEDIATION_ENABLED` | `SECOPS_REMEDIATION_DRY_RUN` | Behaviour |
|---|---|---|
| `false` (default) | — | Engine skipped entirely |
| `true` | `true` (default) | Dispatch runs, audit log written, **no real API calls** |
| `true` | `false` | Full execution — adapters called, approvals queued |

Use `ENABLED=true, DRY_RUN=true` first to validate dispatch logic in production before enabling live execution.

### Swap NoOp adapters for real implementations

When internal API contracts are known, update `runRemediation()` in `cmd/agent/main.go`:

```go
// Before (NoOp):
adapterSet.RateLimiter = adapters.NewNoOpRateLimiter(logger)

// After (HTTP):
adapterSet.RateLimiter = adapters.NewHTTPRateLimiter(baseURL, token)
```

No changes to engine, dispatcher, or audit logic required.

### Traceability: correlate actions to original logs

`request_id` is the end-to-end key:

```bash
# All findings
jq '[.tenant_reports[].findings[].request_id]' output/incident_report.json

# Auto-executed actions
grep '"executed":true' output/remediation_audit.log | jq -r '.request_id'

# Pending human approval
jq -r '.request_id' output/pending_approvals.json
```

Findings whose `request_id` does not appear in either file had no action taken (severity below threshold or attack pattern with no mapped action).

### Verify remediation audit log

```bash
# See all decisions after a run
cat output/remediation_audit.log | jq .

# Filter by action type
grep '"action_type":"rate_limit"' output/remediation_audit.log | jq .

# Check pending approvals
cat output/pending_approvals.json | jq .
```

## Security

Full design rationale is in [DESIGN.md](DESIGN.md):
- Q1: Multi-tenant data isolation strategy
- Q2: Prompt injection threat model for the LLM pipeline
- Q3: Access control model for incident reports
- Q4: Automated remediation engine (Port-and-Adapter pattern, risk model, IM integration, traceability)

**Implemented security properties:**

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
| Remediation isolated from analysis | Engine runs after reports are written; failure cannot corrupt reports |
| Remediation default-safe | `ENABLED=false` + `DRY_RUN=true` by default; no real API calls until explicitly enabled |
| High-risk actions human-gated | `isolate_tenant`, `ban_account` written to `pending_approvals.json`, never auto-executed |
| Remediation audit trail | `remediation_audit.log` records every action decision (executed/dry-run/skipped/pending) |

## What's Next

The following areas are not yet implemented. Each has a clear integration point in the current architecture.

### 1. Connect real internal APIs (replace NoOp adapters)

All four enforcement adapters (`RateLimiter`, `IPBlocker`, `AccountBanner`, `TenantIsolator`) ship as NoOp stubs. Each stub in `internal/remediation/adapters/http.go` has a `// TODO:` comment describing the expected request shape. Once the internal API contract is known:

1. Implement the corresponding `HTTP*` struct method in `http.go`
2. Swap the NoOp for the HTTP implementation in `runRemediation()` inside `cmd/agent/main.go`

No other files need to change.

| Adapter | What's needed |
|---|---|
| `HTTPRateLimiter` | Internal rate-limit API endpoint, request body shape, auth token |
| `HTTPIPBlocker` | Firewall/WAF API endpoint + source IP field (see item 5 below) |
| `HTTPAccountBanner` | Account management API endpoint + user identifier field |
| `HTTPTenantIsolator` | Tenant management API endpoint + isolation level parameter |

### 2. IM integration — Feishu / Slack notification body

`HTTPNotifier` in `adapters/http.go` is a stub with `// TODO:` comments showing the expected Feishu and Slack webhook message shapes. Implementation requires:

- Feishu card message template for security alerts (`approval_required=false`)
- Feishu interactive card with Approve/Reject buttons for approval requests (`approval_required=true`)
- Equivalent Slack Block Kit templates
- Set `SECOPS_NOTIFIER_WEBHOOK_URL` (and optionally `SECOPS_NOTIFIER_APPROVAL_WEBHOOK_URL`) to activate

### 3. Human approval feedback loop

Currently, high-risk actions are written to `pending_approvals.json` and an IM notification is sent, but clicking Approve in the IM does nothing yet. Closing this loop requires:

- A `POST /remediation/approve?key=<dedupe_key>` endpoint in `serve` mode
- A `POST /remediation/reject?key=<dedupe_key>` endpoint
- On approval: look up the `dedupe_key` in `pending_approvals.json`, call the appropriate adapter, update status to `"approved"`
- The existing JWT middleware in `internal/server/auth.go` can be reused; only `secops-admin` should be permitted to approve

The `dedupe_key` field already exists in every `pending_approvals.json` entry as the lookup key.

### 4. Web UI for remediation management

A minimal frontend on top of the existing `serve` mode could expose:

| Page | Data source |
|---|---|
| Pending approvals queue | New `GET /remediation/pending` endpoint |
| Remediation history | New `GET /remediation/history` endpoint (reads `remediation_audit.log`) |
| Finding detail (click through from request_id) | Existing `GET /api/v1/reports/{tenant_id}` |

RBAC is already in place — Approve actions would be restricted to `secops-admin`.

### 5. Source IP threading for `block_ip`

`LLMFinding` does not currently carry a source IP (PII is stripped before the LLM call). The `block_ip` action therefore records `tenant_id` and `request_id` but cannot pass an IP to the firewall API. Two options:

- **Option A**: Add a `RequestIDToIP map[string]string` to `AnalyzedBatch`, populated from `RawLog.HttpRequest.RemoteIP` after sanitization — passed to the Remediation Engine without ever entering the LLM context.
- **Option B**: Add a `SourceIP` field to `LLMFinding` and populate it in a post-sanitization enrichment step.

### 6. Cross-run idempotency

The current dedup map is in-memory and resets on every pipeline run. If the same log file is re-analyzed, remediation actions will fire again. Fix: at engine startup, load all `dedupe_key` values from `remediation_audit.log` into the `seen` map before processing. The file is JSON Lines, so loading is O(n) with minimal overhead.

### 7. CVE database validation

CVE identifiers are currently validated for format (`CVE-YYYY-NNNN...`) and stripped if malformed. A future extension could cross-check them against the NVD API or an internal CVE feed to confirm existence before including them in reports.

### 8. Add a new LLM provider

The `llm.Client` interface makes swapping providers straightforward:

1. Create `internal/llm/openai.go` (or `vertex.go`, etc.)
2. Implement `llm.Client`:
   ```go
   type OpenAIClient struct { ... }
   func (c *OpenAIClient) Analyze(ctx context.Context, batch models.SanitizedBatch) ([]byte, error) { ... }
   ```
3. Add a `case "openai":` branch in `cmd/agent/main.go`

No other changes required — the interface boundary ensures the rest of the pipeline is unaffected.

---

## Scope Note

- CVE handling currently validates identifier format (`CVE-YYYY-NNNN...`) and strips malformed entries. Existence checks against external CVE databases are an optional future extension (see What's Next above).
