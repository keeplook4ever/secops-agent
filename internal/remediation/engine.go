package remediation

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"secops-agent/pkg/models"
)

// Config holds the remediation-specific configuration subset.
type Config struct {
	Enabled     bool
	DryRun      bool
	MinSeverity string // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
	BlockIPRisk RiskLevel
}

// Engine is the top-level orchestrator of the remediation pipeline.
// It processes AnalyzedBatches, dispatches actions, enforces dedup,
// and routes actions to auto-execution or the human-approval queue.
type Engine struct {
	cfg        Config
	adapters   AdapterSet
	dispatcher *Dispatcher
	auditLog   *RemediationAuditLogger
	approvals  *PendingApprovalWriter
	logger     *slog.Logger

	// seen is an in-memory dedup store: dedupeKey → struct{}.
	// Prevents double-execution within a single pipeline run.
	// NOTE: dedup is per-run only. Cross-run dedup requires loading
	// existing keys from remediation_audit.log at startup (future improvement).
	seen map[string]struct{}
	mu   sync.Mutex
}

// New creates an Engine with the given configuration and dependencies.
func New(
	cfg Config,
	adapters AdapterSet,
	auditLog *RemediationAuditLogger,
	approvals *PendingApprovalWriter,
	logger *slog.Logger,
) *Engine {
	return &Engine{
		cfg:        cfg,
		adapters:   adapters,
		dispatcher: NewDispatcher(cfg.BlockIPRisk),
		auditLog:   auditLog,
		approvals:  approvals,
		logger:     logger,
		seen:       make(map[string]struct{}),
	}
}

// Run processes all batches from a single pipeline run.
// It never returns a fatal error — remediation failures are logged but must
// not abort the pipeline after reports have already been written.
func (e *Engine) Run(ctx context.Context, batches []models.AnalyzedBatch) error {
	var errs []string
	for _, batch := range batches {
		for _, finding := range batch.Findings {
			if err := e.processFinding(ctx, batch.TenantID, batch.Scope, finding); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("remediation: %d error(s): %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// processFinding maps one LLMFinding to ActionSpecs, deduplicates, then
// either auto-executes (low-risk) or queues for human approval (high-risk).
func (e *Engine) processFinding(
	ctx context.Context,
	tenantID string,
	scope models.LogScope,
	f models.LLMFinding,
) error {
	// Filter by minimum severity.
	if !e.severityMeetsThreshold(f.Severity) {
		return nil
	}

	specs := e.dispatcher.Dispatch(f.Severity, f.AttackPattern, scope)
	if len(specs) == 0 {
		return nil
	}

	for _, s := range specs {
		// Fill in finding-specific context.
		s.TenantID = tenantID
		s.RequestID = f.RequestID
		s.Severity = f.Severity
		s.AttackPattern = f.AttackPattern
		s.DedupeKey = dedupeKey(f.RequestID, s.ActionType)
		if s.Meta == nil {
			s.Meta = make(map[string]string)
		}

		outcome := e.execute(ctx, s)
		e.auditLog.Log(outcome)
	}
	return nil
}

// execute runs a single ActionSpec through the full decision tree:
// dedup → dry-run → human gate → adapter call.
func (e *Engine) execute(ctx context.Context, s ActionSpec) ActionOutcome {
	// Dedup check.
	if e.isDuplicate(s.DedupeKey) {
		e.logger.Debug("remediation: skipping duplicate action",
			"action", s.ActionType, "request_id", s.RequestID, "key", s.DedupeKey)
		return ActionOutcome{Spec: s, Skipped: true}
	}

	// Dry-run mode: log intent, do not call adapters.
	if e.cfg.DryRun {
		e.logger.Info("remediation [DRY-RUN] would execute action",
			"action", s.ActionType,
			"risk", s.RiskLevel,
			"tenant_id", s.TenantID,
			"request_id", s.RequestID,
			"severity", s.Severity,
			"pattern", s.AttackPattern,
		)
		return ActionOutcome{Spec: s, DryRun: true}
	}

	// Human gate: high-risk actions require human approval before execution.
	if s.RiskLevel == RiskHigh {
		// Mark as approval-required in Meta so the Notifier sends the right message.
		s.Meta["approval_required"] = "true"
		e.approvals.Write(s)

		// Notify the on-call team that a high-risk action is pending approval.
		if e.adapters.Notifier != nil {
			if err := e.adapters.Notifier.Notify(ctx, s); err != nil {
				e.logger.Error("remediation: notifier error for pending approval",
					"action", s.ActionType, "request_id", s.RequestID, "error", err)
			}
		}

		e.logger.Info("remediation: high-risk action queued for human approval",
			"action", s.ActionType,
			"tenant_id", s.TenantID,
			"request_id", s.RequestID,
			"dedupe_key", s.DedupeKey,
		)
		return ActionOutcome{Spec: s, Pending: true}
	}

	// Low-risk: auto-execute via the appropriate adapter.
	err := e.callAdapter(ctx, s)
	if err != nil {
		e.logger.Error("remediation: adapter error",
			"action", s.ActionType, "request_id", s.RequestID, "error", err)
		return ActionOutcome{Spec: s, Err: err}
	}
	e.logger.Info("remediation: action executed",
		"action", s.ActionType,
		"tenant_id", s.TenantID,
		"request_id", s.RequestID,
	)
	return ActionOutcome{Spec: s, Executed: true}
}

// callAdapter routes an ActionSpec to the correct adapter.
func (e *Engine) callAdapter(ctx context.Context, s ActionSpec) error {
	switch s.ActionType {
	case ActionRateLimit:
		if e.adapters.RateLimiter == nil {
			return fmt.Errorf("no RateLimiter adapter configured")
		}
		return e.adapters.RateLimiter.RateLimit(ctx, s)
	case ActionBlockIP:
		if e.adapters.IPBlocker == nil {
			return fmt.Errorf("no IPBlocker adapter configured")
		}
		return e.adapters.IPBlocker.BlockIP(ctx, s)
	case ActionBanAccount:
		if e.adapters.AccountBanner == nil {
			return fmt.Errorf("no AccountBanner adapter configured")
		}
		return e.adapters.AccountBanner.BanAccount(ctx, s)
	case ActionIsolateTenant:
		if e.adapters.TenantIsolator == nil {
			return fmt.Errorf("no TenantIsolator adapter configured")
		}
		return e.adapters.TenantIsolator.IsolateTenant(ctx, s)
	case ActionNotify:
		if e.adapters.Notifier == nil {
			return nil // notify is optional; skip silently if not configured
		}
		return e.adapters.Notifier.Notify(ctx, s)
	default:
		return fmt.Errorf("unknown action type: %q", s.ActionType)
	}
}

// isDuplicate returns true if the key was already seen this run.
// If not seen, it records the key and returns false.
func (e *Engine) isDuplicate(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.seen[key]; ok {
		return true
	}
	e.seen[key] = struct{}{}
	return false
}

// severityMeetsThreshold returns true if the given severity is at or above
// the configured minimum severity.
func (e *Engine) severityMeetsThreshold(severity string) bool {
	order := map[string]int{
		"CRITICAL": 5,
		"HIGH":     4,
		"MEDIUM":   3,
		"LOW":      2,
		"INFO":     1,
	}
	minOrder, ok := order[strings.ToUpper(e.cfg.MinSeverity)]
	if !ok {
		minOrder = order["HIGH"] // safe default
	}
	sevOrder, ok := order[strings.ToUpper(severity)]
	if !ok {
		return false
	}
	return sevOrder >= minOrder
}

// dedupeKey returns a sha256 hex digest of (requestID, actionType).
// Used to prevent double-execution of the same action for the same finding.
func dedupeKey(requestID string, a ActionType) string {
	h := sha256.Sum256([]byte(requestID + "|" + string(a)))
	return fmt.Sprintf("%x", h)
}
