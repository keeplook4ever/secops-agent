package remediation

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// PendingApproval represents a high-risk remediation action that requires human
// sign-off before execution. Written as JSON Lines to an append-only file.
//
// Future: a /remediation/approve?key=<dedupe_key> endpoint in serve mode can
// read this file, execute the action via the appropriate adapter, and update
// status to "approved". The dedupe_key is the lookup key.
type PendingApproval struct {
	CreatedAt     string            `json:"created_at"`
	TenantID      string            `json:"tenant_id"`
	RequestID     string            `json:"request_id"`
	ActionType    string            `json:"action_type"`
	Severity      string            `json:"severity"`
	AttackPattern string            `json:"attack_pattern"`
	DedupeKey     string            `json:"dedupe_key"`
	Meta          map[string]string `json:"meta,omitempty"`
	Status        string            `json:"status"` // "pending" when written; updated externally on approval
}

// PendingApprovalWriter writes pending approval records to an append-only
// JSON Lines file. Safe for concurrent use.
//
// Note: concurrent writes from multiple process invocations would require
// OS-level file locking. Within a single process this mutex is sufficient.
type PendingApprovalWriter struct {
	mu   sync.Mutex
	file *os.File
}

// NewPendingApprovalWriter opens (or creates) the pending approvals file in
// append-only mode.
func NewPendingApprovalWriter(path string) (*PendingApprovalWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("pending approvals: open %q: %w", path, err)
	}
	return &PendingApprovalWriter{file: f}, nil
}

// Write appends a pending approval entry. Write failures are printed to stderr
// but must not break the pipeline.
func (w *PendingApprovalWriter) Write(spec ActionSpec) {
	entry := PendingApproval{
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		TenantID:      spec.TenantID,
		RequestID:     spec.RequestID,
		ActionType:    string(spec.ActionType),
		Severity:      spec.Severity,
		AttackPattern: spec.AttackPattern,
		DedupeKey:     spec.DedupeKey,
		Meta:          spec.Meta,
		Status:        "pending",
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pending approvals: marshal error: %v\n", err)
		return
	}
	data = append(data, '\n')
	if _, err := w.file.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "pending approvals: write error: %v\n", err)
	}
}

// Close closes the pending approvals file.
func (w *PendingApprovalWriter) Close() error {
	return w.file.Close()
}
