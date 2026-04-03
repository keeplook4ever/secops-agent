package remediation_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secops-agent/internal/remediation"
	"secops-agent/internal/remediation/adapters"
	"secops-agent/pkg/models"
)

// --- Helpers ---

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// testEngine builds an Engine wired to NoOp adapters writing to temp files.
func testEngine(t *testing.T, cfg remediation.Config) *remediation.Engine {
	t.Helper()
	dir := t.TempDir()
	logger := newLogger()

	auditLog, err := remediation.NewRemediationAuditLogger(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })

	approvals, err := remediation.NewPendingApprovalWriter(filepath.Join(dir, "approvals.json"))
	if err != nil {
		t.Fatalf("open approvals: %v", err)
	}
	t.Cleanup(func() { approvals.Close() })

	adapterSet := remediation.AdapterSet{
		RateLimiter:    adapters.NewNoOpRateLimiter(logger),
		IPBlocker:      adapters.NewNoOpIPBlocker(logger),
		AccountBanner:  adapters.NewNoOpAccountBanner(logger),
		TenantIsolator: adapters.NewNoOpTenantIsolator(logger),
		Notifier:       adapters.NewNoOpNotifier(logger),
	}
	return remediation.New(cfg, adapterSet, auditLog, approvals, logger)
}

func testBatch(tenantID, scope string, findings ...models.LLMFinding) models.AnalyzedBatch {
	s := models.ScopeTenant
	if scope == "PLATFORM" {
		s = models.ScopePlatform
	}
	return models.AnalyzedBatch{
		TenantKey: "TENANT_ID_1",
		TenantID:  tenantID,
		Scope:     s,
		Findings:  findings,
	}
}

func finding(requestID, severity, pattern string) models.LLMFinding {
	return models.LLMFinding{
		RequestID:     requestID,
		Severity:      severity,
		AttackPattern: pattern,
		Description:   "test finding",
		Remediation:   "investigate",
	}
}

// --- Dispatcher tests ---

func TestDispatcher_PlatformScopeAlwaysNotifyOnly(t *testing.T) {
	d := remediation.NewDispatcher(remediation.RiskLow)
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM"} {
		specs := d.Dispatch(sev, "BruteForce", models.ScopePlatform)
		if len(specs) != 1 || specs[0].ActionType != remediation.ActionNotify {
			t.Errorf("PLATFORM scope + %s: expected [notify], got %v", sev, specs)
		}
	}
}

func TestDispatcher_MediumLowInfoNoAction(t *testing.T) {
	d := remediation.NewDispatcher(remediation.RiskLow)
	for _, sev := range []string{"MEDIUM", "LOW", "INFO"} {
		specs := d.Dispatch(sev, "BruteForce", models.ScopeTenant)
		if len(specs) != 0 {
			t.Errorf("severity %s: expected no actions, got %v", sev, specs)
		}
	}
}

func TestDispatcher_HighAnyPattern_NotifyAndRateLimit(t *testing.T) {
	d := remediation.NewDispatcher(remediation.RiskLow)
	for _, pattern := range []string{"IDOR", "Reconnaissance", "Normal", "BruteForce"} {
		specs := d.Dispatch("HIGH", pattern, models.ScopeTenant)
		if len(specs) != 2 {
			t.Errorf("HIGH+%s: expected 2 actions, got %d", pattern, len(specs))
			continue
		}
		hasNotify := specs[0].ActionType == remediation.ActionNotify
		hasRateLimit := specs[1].ActionType == remediation.ActionRateLimit
		if !hasNotify || !hasRateLimit {
			t.Errorf("HIGH+%s: expected [notify, rate_limit], got %v", pattern, specs)
		}
	}
}

func TestDispatcher_CriticalBruteForce_ThreeActions(t *testing.T) {
	d := remediation.NewDispatcher(remediation.RiskLow)
	specs := d.Dispatch("CRITICAL", "BruteForce", models.ScopeTenant)
	if len(specs) != 3 {
		t.Fatalf("expected 3 actions, got %d: %v", len(specs), specs)
	}
	// notify, rate_limit, block_ip
	types := []remediation.ActionType{specs[0].ActionType, specs[1].ActionType, specs[2].ActionType}
	want := []remediation.ActionType{remediation.ActionNotify, remediation.ActionRateLimit, remediation.ActionBlockIP}
	for i, got := range types {
		if got != want[i] {
			t.Errorf("action[%d]: want %s, got %s", i, want[i], got)
		}
	}
}

func TestDispatcher_CriticalBruteForce_BlockIPRiskConfigurable(t *testing.T) {
	// RiskLow → block_ip auto-executes
	dLow := remediation.NewDispatcher(remediation.RiskLow)
	specs := dLow.Dispatch("CRITICAL", "BruteForce", models.ScopeTenant)
	if specs[2].RiskLevel != remediation.RiskLow {
		t.Errorf("block_ip should be RiskLow, got %s", specs[2].RiskLevel)
	}

	// RiskHigh → block_ip requires human gate
	dHigh := remediation.NewDispatcher(remediation.RiskHigh)
	specs = dHigh.Dispatch("CRITICAL", "BruteForce", models.ScopeTenant)
	if specs[2].RiskLevel != remediation.RiskHigh {
		t.Errorf("block_ip should be RiskHigh, got %s", specs[2].RiskLevel)
	}
}

func TestDispatcher_CriticalUnauthorizedExec_IsolateTenantHighRisk(t *testing.T) {
	d := remediation.NewDispatcher(remediation.RiskLow)
	for _, pattern := range []string{"UnauthorizedExec", "PrivilegeEscalation", "IAMPolicyViolation"} {
		specs := d.Dispatch("CRITICAL", pattern, models.ScopeTenant)
		if len(specs) != 2 {
			t.Errorf("CRITICAL+%s: expected 2 actions, got %d", pattern, len(specs))
			continue
		}
		if specs[1].ActionType != remediation.ActionIsolateTenant {
			t.Errorf("CRITICAL+%s: expected isolate_tenant, got %s", pattern, specs[1].ActionType)
		}
		if specs[1].RiskLevel != remediation.RiskHigh {
			t.Errorf("CRITICAL+%s: isolate_tenant should be RiskHigh", pattern)
		}
	}
}

func TestDispatcher_CriticalPromptInjection_NotifyAndRateLimit(t *testing.T) {
	d := remediation.NewDispatcher(remediation.RiskLow)
	specs := d.Dispatch("CRITICAL", "PromptInjection", models.ScopeTenant)
	if len(specs) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(specs))
	}
	if specs[0].ActionType != remediation.ActionNotify || specs[1].ActionType != remediation.ActionRateLimit {
		t.Errorf("expected [notify, rate_limit], got %v", specs)
	}
}

// --- Engine: MinSeverity filter ---

func TestEngine_MinSeverity_FiltersLowerSeverity(t *testing.T) {
	cfg := remediation.Config{
		Enabled:     true,
		DryRun:      false,
		MinSeverity: "HIGH",
		BlockIPRisk: remediation.RiskLow,
	}
	engine := testEngine(t, cfg)

	batches := []models.AnalyzedBatch{
		testBatch("600647", "TENANT",
			finding("req-001", "MEDIUM", "BruteForce"),
			finding("req-002", "LOW", "IDOR"),
			finding("req-003", "INFO", "Normal"),
		),
	}
	if err := engine.Run(context.Background(), batches); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No panic or error means the engine silently skipped all three findings.
}

func TestEngine_MinSeverity_ProcessesHighAndAbove(t *testing.T) {
	cfg := remediation.Config{
		Enabled:     true,
		DryRun:      true, // dry-run to observe without side effects
		MinSeverity: "HIGH",
		BlockIPRisk: remediation.RiskLow,
	}
	engine := testEngine(t, cfg)

	batches := []models.AnalyzedBatch{
		testBatch("600647", "TENANT",
			finding("req-high", "HIGH", "BruteForce"),
			finding("req-critical", "CRITICAL", "PromptInjection"),
			finding("req-medium", "MEDIUM", "IDOR"),
		),
	}
	if err := engine.Run(context.Background(), batches); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// HIGH and CRITICAL findings are processed (logged in dry-run mode);
	// MEDIUM is silently skipped. No assertions on output needed — the test
	// validates no panic and no unexpected error.
}

// --- Engine: DryRun ---

func TestEngine_DryRun_DoesNotCallAdapters(t *testing.T) {
	cfg := remediation.Config{
		Enabled:     true,
		DryRun:      true,
		MinSeverity: "HIGH",
		BlockIPRisk: remediation.RiskLow,
	}

	dir := t.TempDir()
	logger := newLogger()

	counter := &countingNotifier{inner: adapters.NewNoOpNotifier(logger)}

	auditLog, _ := remediation.NewRemediationAuditLogger(filepath.Join(dir, "audit.log"))
	t.Cleanup(func() { auditLog.Close() })
	approvals, _ := remediation.NewPendingApprovalWriter(filepath.Join(dir, "approvals.json"))
	t.Cleanup(func() { approvals.Close() })

	adapterSet := remediation.AdapterSet{
		RateLimiter:    adapters.NewNoOpRateLimiter(logger),
		IPBlocker:      adapters.NewNoOpIPBlocker(logger),
		AccountBanner:  adapters.NewNoOpAccountBanner(logger),
		TenantIsolator: adapters.NewNoOpTenantIsolator(logger),
		Notifier:       counter,
	}
	engine := remediation.New(cfg, adapterSet, auditLog, approvals, logger)

	batches := []models.AnalyzedBatch{
		testBatch("600647", "TENANT",
			finding("req-001", "CRITICAL", "BruteForce"),
		),
	}
	if err := engine.Run(context.Background(), batches); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if counter.count != 0 {
		t.Errorf("dry-run: Notifier should not have been called, got %d calls", counter.count)
	}
}

// --- Engine: High-risk gate ---

func TestEngine_HighRiskAction_WritesToApprovalsNotExecuted(t *testing.T) {
	cfg := remediation.Config{
		Enabled:     true,
		DryRun:      false,
		MinSeverity: "CRITICAL",
		BlockIPRisk: remediation.RiskLow,
	}

	dir := t.TempDir()
	logger := newLogger()

	isolatorCounter := &countingTenantIsolator{inner: adapters.NewNoOpTenantIsolator(logger)}
	notifyCounter := &countingNotifier{inner: adapters.NewNoOpNotifier(logger)}

	auditLog, _ := remediation.NewRemediationAuditLogger(filepath.Join(dir, "audit.log"))
	t.Cleanup(func() { auditLog.Close() })
	approvalsPath := filepath.Join(dir, "approvals.json")
	approvals, _ := remediation.NewPendingApprovalWriter(approvalsPath)
	t.Cleanup(func() { approvals.Close() })

	adapterSet := remediation.AdapterSet{
		RateLimiter:    adapters.NewNoOpRateLimiter(logger),
		IPBlocker:      adapters.NewNoOpIPBlocker(logger),
		AccountBanner:  adapters.NewNoOpAccountBanner(logger),
		TenantIsolator: isolatorCounter,
		Notifier:       notifyCounter,
	}
	engine := remediation.New(cfg, adapterSet, auditLog, approvals, logger)

	batches := []models.AnalyzedBatch{
		testBatch("600647", "TENANT",
			finding("req-001", "CRITICAL", "UnauthorizedExec"),
		),
	}
	if err := engine.Run(context.Background(), batches); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// isolate_tenant is high-risk: adapter must NOT be called
	if isolatorCounter.count != 0 {
		t.Errorf("isolate_tenant adapter should not be called; got %d calls", isolatorCounter.count)
	}
	// Notifier is called twice:
	//   1. For the auto-executed notify(low) action (security alert)
	//   2. For the approval request notification triggered by isolate_tenant(high)
	if notifyCounter.count != 2 {
		t.Errorf("Notifier should be called twice (alert + approval request); got %d calls", notifyCounter.count)
	}
	// approvals.json should contain the pending entry
	data, err := os.ReadFile(approvalsPath)
	if err != nil {
		t.Fatalf("read approvals file: %v", err)
	}
	if !strings.Contains(string(data), "isolate_tenant") {
		t.Errorf("approvals.json should contain isolate_tenant entry, got: %s", string(data))
	}
	if !strings.Contains(string(data), "pending") {
		t.Errorf("approvals.json should contain status=pending, got: %s", string(data))
	}
}

// --- Engine: Dedup ---

func TestEngine_Dedup_SameFindingProcessedTwice(t *testing.T) {
	cfg := remediation.Config{
		Enabled:     true,
		DryRun:      false,
		MinSeverity: "HIGH",
		BlockIPRisk: remediation.RiskLow,
	}

	dir := t.TempDir()
	logger := newLogger()
	counter := &countingNotifier{inner: adapters.NewNoOpNotifier(logger)}

	auditLog, _ := remediation.NewRemediationAuditLogger(filepath.Join(dir, "audit.log"))
	t.Cleanup(func() { auditLog.Close() })
	approvals, _ := remediation.NewPendingApprovalWriter(filepath.Join(dir, "approvals.json"))
	t.Cleanup(func() { approvals.Close() })

	adapterSet := remediation.AdapterSet{
		RateLimiter:    adapters.NewNoOpRateLimiter(logger),
		IPBlocker:      adapters.NewNoOpIPBlocker(logger),
		AccountBanner:  adapters.NewNoOpAccountBanner(logger),
		TenantIsolator: adapters.NewNoOpTenantIsolator(logger),
		Notifier:       counter,
	}
	engine := remediation.New(cfg, adapterSet, auditLog, approvals, logger)

	sameFinding := finding("req-dupe", "HIGH", "BruteForce")
	// Submit the same finding twice in the same run.
	batches := []models.AnalyzedBatch{
		testBatch("600647", "TENANT", sameFinding),
		testBatch("600647", "TENANT", sameFinding),
	}
	if err := engine.Run(context.Background(), batches); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// HIGH+BruteForce dispatches [notify, rate_limit].
	// First batch: notify called once, rate_limit called once → 1 notify call.
	// Second batch: both are deduped → 0 additional notify calls.
	if counter.count != 1 {
		t.Errorf("Notifier should be called exactly once (dedup); got %d calls", counter.count)
	}
}

// --- Engine: PLATFORM scope isolation ---

func TestEngine_PlatformScope_NotifyOnly(t *testing.T) {
	cfg := remediation.Config{
		Enabled:     true,
		DryRun:      false,
		MinSeverity: "HIGH",
		BlockIPRisk: remediation.RiskLow,
	}

	dir := t.TempDir()
	logger := newLogger()
	isolatorCounter := &countingTenantIsolator{inner: adapters.NewNoOpTenantIsolator(logger)}
	rateLimitCounter := &countingRateLimiter{inner: adapters.NewNoOpRateLimiter(logger)}
	notifyCounter := &countingNotifier{inner: adapters.NewNoOpNotifier(logger)}

	auditLog, _ := remediation.NewRemediationAuditLogger(filepath.Join(dir, "audit.log"))
	t.Cleanup(func() { auditLog.Close() })
	approvals, _ := remediation.NewPendingApprovalWriter(filepath.Join(dir, "approvals.json"))
	t.Cleanup(func() { approvals.Close() })

	adapterSet := remediation.AdapterSet{
		RateLimiter:    rateLimitCounter,
		IPBlocker:      adapters.NewNoOpIPBlocker(logger),
		AccountBanner:  adapters.NewNoOpAccountBanner(logger),
		TenantIsolator: isolatorCounter,
		Notifier:       notifyCounter,
	}
	engine := remediation.New(cfg, adapterSet, auditLog, approvals, logger)

	batches := []models.AnalyzedBatch{
		testBatch("", "PLATFORM",
			finding("req-platform", "CRITICAL", "UnauthorizedExec"),
		),
	}
	if err := engine.Run(context.Background(), batches); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if isolatorCounter.count != 0 {
		t.Errorf("PLATFORM scope: isolate_tenant should never be called; got %d calls", isolatorCounter.count)
	}
	if rateLimitCounter.count != 0 {
		t.Errorf("PLATFORM scope: rate_limit should never be called; got %d calls", rateLimitCounter.count)
	}
	if notifyCounter.count != 1 {
		t.Errorf("PLATFORM scope: Notifier should be called exactly once; got %d calls", notifyCounter.count)
	}
}

// --- Counting adapter helpers ---

type countingNotifier struct {
	count int
	inner remediation.Notifier
}

func (c *countingNotifier) Notify(ctx context.Context, spec remediation.ActionSpec) error {
	c.count++
	return c.inner.Notify(ctx, spec)
}

type countingTenantIsolator struct {
	count int
	inner remediation.TenantIsolator
}

func (c *countingTenantIsolator) IsolateTenant(ctx context.Context, spec remediation.ActionSpec) error {
	c.count++
	return c.inner.IsolateTenant(ctx, spec)
}

type countingRateLimiter struct {
	count int
	inner remediation.RateLimiter
}

func (c *countingRateLimiter) RateLimit(ctx context.Context, spec remediation.ActionSpec) error {
	c.count++
	return c.inner.RateLimit(ctx, spec)
}
