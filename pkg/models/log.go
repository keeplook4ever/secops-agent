package models

// RawLog represents a single entry from the GKE / API-gateway JSON log file.
// Both log types share the same top-level shape; the logName field is used to
// distinguish TENANT-scoped API gateway logs from PLATFORM-scoped GKE audit logs.
type RawLog struct {
	Timestamp   string      `json:"timestamp"`
	Severity    string      `json:"severity"`
	LogName     string      `json:"logName"`
	HttpRequest HttpRequest `json:"httpRequest"`
	JsonPayload JsonPayload `json:"jsonPayload"`
}

type HttpRequest struct {
	RequestMethod string `json:"requestMethod"`
	Status        int    `json:"status"`
	Latency       string `json:"latency"`
	UserAgent     string `json:"userAgent"`
	RemoteIP      string `json:"remoteIp"`
	RequestURL    string `json:"requestUrl"`
}

type JsonPayload struct {
	TenantID     string `json:"tenant_id"`
	RequestID    string `json:"request_id"`
	UserEmail    string `json:"user_email"`
	DatabaseName string `json:"database_name"`
	XTraceID     string `json:"x-trace-id"`
	ChannelID    string `json:"channel_id"`
	Message      string `json:"message"`
}

// LogScope classifies a log entry's data ownership boundary.
type LogScope string

const (
	// ScopeTenant means the log belongs to a specific customer tenant.
	ScopeTenant LogScope = "TENANT"
	// ScopePlatform means the log is infrastructure-level (GKE audit, IAM, etc.)
	// and has no tenant_id by design.
	ScopePlatform LogScope = "PLATFORM"
)

// ClassifiedLog is a RawLog with its scope and derived tenant key attached.
type ClassifiedLog struct {
	Raw       RawLog
	Scope     LogScope
	TenantID  string // raw tenant_id, empty for PLATFORM
}
