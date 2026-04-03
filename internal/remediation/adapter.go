package remediation

import "context"

// RateLimiter applies rate limiting for a tenant.
// Real implementation calls the internal rate-limit API (see adapters/http.go TODO).
type RateLimiter interface {
	RateLimit(ctx context.Context, spec ActionSpec) error
}

// IPBlocker blocks a source IP address.
// Real implementation calls the internal firewall/WAF API (see adapters/http.go TODO).
// Note: ActionSpec.Meta["ip"] will carry the source IP once the pipeline is enriched
// to thread RawLog.HttpRequest.RemoteIP through to findings.
type IPBlocker interface {
	BlockIP(ctx context.Context, spec ActionSpec) error
}

// AccountBanner suspends or bans a user account.
// Real implementation calls the internal account management API (see adapters/http.go TODO).
// Not wired into the default dispatch table — reserved for confirmed account-takeover triggers.
type AccountBanner interface {
	BanAccount(ctx context.Context, spec ActionSpec) error
}

// TenantIsolator isolates a tenant's resources (network, data, or full isolation).
// Real implementation calls the internal tenant management API (see adapters/http.go TODO).
// Always high-risk; requires human approval before execution.
type TenantIsolator interface {
	IsolateTenant(ctx context.Context, spec ActionSpec) error
}

// Notifier sends alerts and approval requests to an IM system (Feishu / Slack).
// When spec.Meta["approval_required"] == "true", the implementation should send
// an interactive approval-request message. Otherwise, a plain security alert.
type Notifier interface {
	Notify(ctx context.Context, spec ActionSpec) error
}

// AdapterSet bundles all five port interfaces so the Engine has a single dependency.
// Any field may be nil; the Engine guards against nil before calling.
type AdapterSet struct {
	RateLimiter    RateLimiter
	IPBlocker      IPBlocker
	AccountBanner  AccountBanner
	TenantIsolator TenantIsolator
	Notifier       Notifier
}
