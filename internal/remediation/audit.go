package remediation

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// RemediationAuditEntry records a single remediation action decision.
// Written as JSON Lines to an append-only file.
// Every action — executed, dry-run, skipped (dedup), or pending (human gate) —
// produces exactly one entry, providing a complete immutable record of every
// remediation decision made by the engine.
type RemediationAuditEntry struct {
	Timestamp     string `json:"ts"`
	TenantID      string `json:"tenant_id"`
	RequestID     string `json:"request_id"`
	ActionType    string `json:"action_type"`
	Severity      string `json:"severity"`
	AttackPattern string `json:"attack_pattern"`
	DedupeKey     string `json:"dedupe_key"`
	DryRun        bool   `json:"dry_run"`
	Executed      bool   `json:"executed"`
	Skipped       bool   `json:"skipped"` // true when dedup key was already seen this run
	Pending       bool   `json:"pending"` // true when written to approval queue
	Error         string `json:"error,omitempty"`
}

// RemediationAuditLogger writes remediation audit entries to an append-only
// JSON Lines file. Safe for concurrent use.
// Mirrors the pattern of internal/server/audit.go.
type RemediationAuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

// NewRemediationAuditLogger opens (or creates) the remediation audit log file
// in append-only mode.
func NewRemediationAuditLogger(path string) (*RemediationAuditLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("remediation audit: open %q: %w", path, err)
	}
	return &RemediationAuditLogger{file: f}, nil
}

// Log writes a remediation audit entry. Audit failures are printed to stderr
// but must not break the pipeline.
func (a *RemediationAuditLogger) Log(outcome ActionOutcome) {
	entry := RemediationAuditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		TenantID:      outcome.Spec.TenantID,
		RequestID:     outcome.Spec.RequestID,
		ActionType:    string(outcome.Spec.ActionType),
		Severity:      outcome.Spec.Severity,
		AttackPattern: outcome.Spec.AttackPattern,
		DedupeKey:     outcome.Spec.DedupeKey,
		DryRun:        outcome.DryRun,
		Executed:      outcome.Executed,
		Skipped:       outcome.Skipped,
		Pending:       outcome.Pending,
	}
	if outcome.Err != nil {
		entry.Error = outcome.Err.Error()
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "remediation audit: marshal error: %v\n", err)
		return
	}
	data = append(data, '\n')
	if _, err := a.file.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "remediation audit: write error: %v\n", err)
	}
}

// Close closes the audit log file.
func (a *RemediationAuditLogger) Close() error {
	return a.file.Close()
}
