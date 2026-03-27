package server

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEntry records a single report-access event.
// Written as JSON Lines to an append-only file, satisfying DESIGN.md Q3:
// "All report access is written to an append-only audit log (separate storage,
// immutable). Provides evidence trail for SOC 2 CC7.2 and CC7.3."
type AuditEntry struct {
	Timestamp string `json:"ts"`
	Role      string `json:"role"`
	Subject   string `json:"sub"`
	TenantID  string `json:"tenant_id,omitempty"`
	Path      string `json:"path"`
	Method    string `json:"method"`
	Status    int    `json:"status"`
}

// AuditLogger writes audit entries to an append-only JSON Lines file.
// Safe for concurrent use.
type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

// NewAuditLogger opens (or creates) the audit log file in append-only mode.
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}
	return &AuditLogger{file: f}, nil
}

// Log writes an audit entry. It never returns an error to the caller;
// audit failures are logged to stderr but must not break the API.
func (a *AuditLogger) Log(entry AuditEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	a.mu.Lock()
	defer a.mu.Unlock()
	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: marshal error: %v\n", err)
		return
	}
	data = append(data, '\n')
	if _, err := a.file.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "audit: write error: %v\n", err)
	}
}

// Close closes the audit log file.
func (a *AuditLogger) Close() error {
	return a.file.Close()
}
