package remediation

// ActionType enumerates every kind of remediation action the engine can dispatch.
type ActionType string

const (
	ActionRateLimit     ActionType = "rate_limit"
	ActionBlockIP       ActionType = "block_ip"
	ActionBanAccount    ActionType = "ban_account"
	ActionIsolateTenant ActionType = "isolate_tenant"
	ActionNotify        ActionType = "notify"
)

// RiskLevel classifies whether an action auto-executes or requires human approval.
type RiskLevel string

const (
	// RiskLow actions are executed automatically.
	RiskLow RiskLevel = "low"
	// RiskHigh actions are written to pending_approvals.json and NOT executed
	// until a human approves them.
	RiskHigh RiskLevel = "high"
)

// ActionSpec is a resolved, ready-to-dispatch action for one finding.
// It carries all context needed by any adapter.
type ActionSpec struct {
	ActionType    ActionType
	RiskLevel     RiskLevel
	TenantID      string
	RequestID     string
	DedupeKey     string            // sha256(request_id + "|" + action_type), hex-encoded
	Severity      string
	AttackPattern string
	// Meta holds optional enrichment fields for future use (e.g. "ip", "email").
	// approval_required="true" signals the Notifier to send an approval request.
	Meta map[string]string
}

// ActionOutcome records the result of processing one ActionSpec through the engine.
type ActionOutcome struct {
	Spec     ActionSpec
	Executed bool  // true when adapter was called successfully
	DryRun   bool  // true when engine is in dry-run mode
	Skipped  bool  // true when dedup key was already seen this run
	Pending  bool  // true when high-risk action was written to approval queue
	Err      error // non-nil if adapter call failed
}
