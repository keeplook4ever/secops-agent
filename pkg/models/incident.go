package models

import "time"

// Severity levels returned by the LLM.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// LLMFinding is the per-event analysis produced by the LLM.
// This is also the schema we validate against before accepting LLM output.
type LLMFinding struct {
	RequestID       string   `json:"request_id"`
	Severity        string   `json:"severity"`
	AttackPattern   string   `json:"attack_pattern"`
	Description     string   `json:"description"`
	SOC2Controls    []string `json:"soc2_controls"`
	CVEs            []string `json:"cves"`
	ConfidenceScore float64  `json:"confidence_score"`
	Remediation     string   `json:"remediation"`
}

// LLMBatchResponse is the exact JSON shape we expect from the LLM for
// one SanitizedBatch. Strict schema validation is applied before use.
type LLMBatchResponse struct {
	TenantKey string       `json:"tenant_key"`
	Findings  []LLMFinding `json:"findings"`
}

// ValidationStatus records whether a batch's LLM response passed validation.
type ValidationStatus string

const (
	ValidationOK             ValidationStatus = "OK"
	ValidationLowConfidence  ValidationStatus = "LOW_CONFIDENCE"
	ValidationSchemaMismatch ValidationStatus = "SCHEMA_MISMATCH"
	ValidationInvalidCVE     ValidationStatus = "INVALID_CVE"
)

// AnalyzedBatch is an LLMBatchResponse enriched with validation metadata.
type AnalyzedBatch struct {
	TenantKey        string
	TenantID         string
	Scope            LogScope
	Findings         []LLMFinding
	ValidationStatus ValidationStatus
	ValidationNotes  []string
	// InjectionCount is the number of log entries in this batch where
	// injection patterns were detected before LLM submission.
	InjectionCount int
}

// IncidentReport is the final structured output written to disk.
type IncidentReport struct {
	GeneratedAt    time.Time      `json:"generated_at"`
	SourceFile     string         `json:"source_file"`
	TotalLogs      int            `json:"total_logs"`
	Summary        ReportSummary  `json:"summary"`
	TenantReports  []TenantReport `json:"tenant_reports"`
	PlatformReport *TenantReport  `json:"platform_report,omitempty"`
}

// ReportSummary provides aggregate counts for quick triage.
type ReportSummary struct {
	CriticalCount             int `json:"critical_count"`
	HighCount                 int `json:"high_count"`
	MediumCount               int `json:"medium_count"`
	LowCount                  int `json:"low_count"`
	InfoCount                 int `json:"info_count"`
	InjectionAttemptsDetected int `json:"injection_attempts_detected"`
}

// TenantReport is the per-tenant section of the incident report.
type TenantReport struct {
	TenantKey        string           `json:"tenant_key"`
	TenantID         string           `json:"tenant_id,omitempty"`
	Scope            string           `json:"scope"`
	LogCount         int              `json:"log_count"`
	Findings         []LLMFinding     `json:"findings"`
	ValidationStatus ValidationStatus `json:"validation_status"`
	ValidationNotes  []string         `json:"validation_notes,omitempty"`
}
