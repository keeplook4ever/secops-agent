package remediation

import "secops-agent/pkg/models"

// Dispatcher maps (severity, attack_pattern, scope) to a list of ActionSpecs.
// It is a pure function with no I/O or side effects, making it trivially testable.
//
// Dispatch rules (applied in order):
//  1. PLATFORM scope → notify only (no tenant-scoped actions ever)
//  2. Severity below HIGH → no action
//  3. CRITICAL + pattern-specific rules
//  4. HIGH → notify + rate_limit
type Dispatcher struct {
	blockIPRisk RiskLevel // configurable: "low" (auto) or "high" (human-gate)
}

// NewDispatcher creates a Dispatcher. blockIPRisk controls whether block_ip
// actions auto-execute ("low") or require human approval ("high").
func NewDispatcher(blockIPRisk RiskLevel) *Dispatcher {
	return &Dispatcher{blockIPRisk: blockIPRisk}
}

// Dispatch returns the list of ActionSpecs to create for a (severity, pattern, scope)
// combination. It does NOT set TenantID, RequestID, or DedupeKey — those are
// filled by the Engine before execution.
// Returns nil when no action should be taken.
func (d *Dispatcher) Dispatch(severity, pattern string, scope models.LogScope) []ActionSpec {
	// Rule 1: PLATFORM scope — infrastructure findings trigger alerts only.
	// No tenant resource should ever be touched by a platform-level finding.
	if scope == models.ScopePlatform {
		return []ActionSpec{notify(RiskLow)}
	}

	// Rules 2-4: tenant-scoped findings.
	switch severity {
	case string(models.SeverityCritical):
		return d.dispatchCritical(pattern)
	case string(models.SeverityHigh):
		return []ActionSpec{notify(RiskLow), spec(ActionRateLimit, RiskLow)}
	default:
		// MEDIUM, LOW, INFO — no automated action.
		return nil
	}
}

// dispatchCritical returns actions for CRITICAL severity findings.
func (d *Dispatcher) dispatchCritical(pattern string) []ActionSpec {
	switch pattern {
	case "BruteForce", "CredentialStuffing":
		return []ActionSpec{
			notify(RiskLow),
			spec(ActionRateLimit, RiskLow),
			spec(ActionBlockIP, d.blockIPRisk),
		}
	case "PromptInjection":
		return []ActionSpec{
			notify(RiskLow),
			spec(ActionRateLimit, RiskLow),
		}
	case "UnauthorizedExec", "PrivilegeEscalation", "IAMPolicyViolation":
		return []ActionSpec{
			notify(RiskLow),
			spec(ActionIsolateTenant, RiskHigh),
		}
	default:
		// IDOR, RateLimitBypass, Reconnaissance, Misconfiguration, Normal, etc.
		return []ActionSpec{notify(RiskLow)}
	}
}

// notify returns a notify ActionSpec with the given risk level.
func notify(risk RiskLevel) ActionSpec {
	return spec(ActionNotify, risk)
}

// spec returns an ActionSpec with only ActionType and RiskLevel set.
// Engine fills the remaining fields (TenantID, RequestID, DedupeKey, etc.)
// from the finding context.
func spec(a ActionType, risk RiskLevel) ActionSpec {
	return ActionSpec{
		ActionType: a,
		RiskLevel:  risk,
	}
}
