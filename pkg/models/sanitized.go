package models

// SanitizedLog is a log entry after all PII / secret redaction and
// prompt-injection detection. This is the only form of data that ever
// reaches the LLM API.
type SanitizedLog struct {
	// OriginalRequestID is kept for correlation in the final report.
	OriginalRequestID string
	Scope             LogScope
	// TenantKey is the opaque placeholder (e.g. "TENANT_ID_1") that
	// replaces the real tenant_id in LLM context.
	TenantKey string

	// Sanitized HTTP fields
	Timestamp  string
	Severity   string
	LogName    string
	Method     string
	Status     int
	Latency    string
	UserAgent  string
	RemoteIP   string // e.g. REDACTED_IP or INTERNAL_IP
	RequestURL string // host+path only, query params redacted

	// Sanitized payload fields
	UserEmail    string // REDACTED_EMAIL
	DatabaseName string // REDACTED_DB
	Message      string // may contain [FLAGGED_INJECTION_ATTEMPT]

	// Injection metadata — never sent to LLM verbatim.
	InjectionDetected bool
	InjectionPatterns []string
}

// SanitizedBatch groups sanitized logs that may be sent together in a
// single LLM call. All logs in a batch share the same TenantKey.
type SanitizedBatch struct {
	TenantKey string
	Scope     LogScope
	Logs      []SanitizedLog
}
