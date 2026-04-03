// Package adapters provides concrete implementations of the remediation port interfaces.
// NoOp stubs are safe defaults: they log intent without calling any real API.
// HTTP stubs are compile-time-checked templates that panic at runtime until implemented.
package adapters

import (
	"context"
	"log/slog"

	"secops-agent/internal/remediation"
)

// --- NoOpRateLimiter ---

// NoOpRateLimiter satisfies remediation.RateLimiter without calling any real API.
type NoOpRateLimiter struct{ logger *slog.Logger }

func NewNoOpRateLimiter(logger *slog.Logger) *NoOpRateLimiter {
	return &NoOpRateLimiter{logger: logger}
}

func (a *NoOpRateLimiter) RateLimit(_ context.Context, spec remediation.ActionSpec) error {
	a.logger.Info("[NOOP] would execute rate_limit",
		"tenant_id", spec.TenantID,
		"request_id", spec.RequestID,
		"severity", spec.Severity,
		"pattern", spec.AttackPattern,
	)
	return nil
}

// --- NoOpIPBlocker ---

// NoOpIPBlocker satisfies remediation.IPBlocker without calling any real API.
type NoOpIPBlocker struct{ logger *slog.Logger }

func NewNoOpIPBlocker(logger *slog.Logger) *NoOpIPBlocker {
	return &NoOpIPBlocker{logger: logger}
}

func (a *NoOpIPBlocker) BlockIP(_ context.Context, spec remediation.ActionSpec) error {
	a.logger.Info("[NOOP] would execute block_ip",
		"tenant_id", spec.TenantID,
		"request_id", spec.RequestID,
		"ip", spec.Meta["ip"], // empty until pipeline is enriched with source IP
	)
	return nil
}

// --- NoOpAccountBanner ---

// NoOpAccountBanner satisfies remediation.AccountBanner without calling any real API.
type NoOpAccountBanner struct{ logger *slog.Logger }

func NewNoOpAccountBanner(logger *slog.Logger) *NoOpAccountBanner {
	return &NoOpAccountBanner{logger: logger}
}

func (a *NoOpAccountBanner) BanAccount(_ context.Context, spec remediation.ActionSpec) error {
	a.logger.Info("[NOOP] would execute ban_account",
		"tenant_id", spec.TenantID,
		"request_id", spec.RequestID,
	)
	return nil
}

// --- NoOpTenantIsolator ---

// NoOpTenantIsolator satisfies remediation.TenantIsolator without calling any real API.
type NoOpTenantIsolator struct{ logger *slog.Logger }

func NewNoOpTenantIsolator(logger *slog.Logger) *NoOpTenantIsolator {
	return &NoOpTenantIsolator{logger: logger}
}

func (a *NoOpTenantIsolator) IsolateTenant(_ context.Context, spec remediation.ActionSpec) error {
	a.logger.Info("[NOOP] would execute isolate_tenant",
		"tenant_id", spec.TenantID,
		"request_id", spec.RequestID,
		"severity", spec.Severity,
		"pattern", spec.AttackPattern,
	)
	return nil
}

// --- NoOpNotifier ---

// NoOpNotifier satisfies remediation.Notifier without calling any real IM system.
type NoOpNotifier struct{ logger *slog.Logger }

func NewNoOpNotifier(logger *slog.Logger) *NoOpNotifier {
	return &NoOpNotifier{logger: logger}
}

func (a *NoOpNotifier) Notify(_ context.Context, spec remediation.ActionSpec) error {
	if spec.Meta["approval_required"] == "true" {
		a.logger.Info("[NOOP] would send approval request to IM",
			"action", spec.ActionType,
			"tenant_id", spec.TenantID,
			"request_id", spec.RequestID,
			"severity", spec.Severity,
		)
	} else {
		a.logger.Info("[NOOP] would send security alert to IM",
			"severity", spec.Severity,
			"pattern", spec.AttackPattern,
			"tenant_id", spec.TenantID,
			"request_id", spec.RequestID,
		)
	}
	return nil
}
