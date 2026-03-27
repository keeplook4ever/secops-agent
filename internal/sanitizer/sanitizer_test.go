package sanitizer

import (
	"strings"
	"testing"

	"github.com/wati/secops-agent/pkg/models"
)

func TestGroupIntoBatches_SeparatesTenantMissingAndPlatform(t *testing.T) {
	s := New()

	tenantMissing := s.Sanitize(models.ClassifiedLog{
		Scope:    models.ScopeTenant,
		TenantID: "",
		Raw: models.RawLog{
			JsonPayload: models.JsonPayload{RequestID: "req-tenant-missing", Message: "hello"},
		},
	})
	platform := s.Sanitize(models.ClassifiedLog{
		Scope:    models.ScopePlatform,
		TenantID: "",
		Raw: models.RawLog{
			JsonPayload: models.JsonPayload{RequestID: "req-platform", Message: "hello"},
		},
	})

	batches := s.GroupIntoBatches([]models.SanitizedLog{tenantMissing, platform})
	if len(batches) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(batches))
	}

	byKey := map[string]models.SanitizedBatch{}
	for _, b := range batches {
		byKey[b.TenantKey] = b
	}

	if _, ok := byKey["TENANT_ID_MISSING"]; !ok {
		t.Fatalf("expected TENANT_ID_MISSING batch, got keys: %v", keys(byKey))
	}
	if byKey["TENANT_ID_MISSING"].Scope != models.ScopeTenant {
		t.Fatalf("TENANT_ID_MISSING batch should be TENANT scope, got %s", byKey["TENANT_ID_MISSING"].Scope)
	}
	if _, ok := byKey["PLATFORM"]; !ok {
		t.Fatalf("expected PLATFORM batch, got keys: %v", keys(byKey))
	}
	if byKey["PLATFORM"].Scope != models.ScopePlatform {
		t.Fatalf("PLATFORM batch should be PLATFORM scope, got %s", byKey["PLATFORM"].Scope)
	}
}

func TestSanitize_RedactsUserAgentWhenNoInjection(t *testing.T) {
	s := New()
	log := s.Sanitize(models.ClassifiedLog{
		Scope:    models.ScopeTenant,
		TenantID: "600647",
		Raw: models.RawLog{
			HttpRequest: models.HttpRequest{
				UserAgent: "app/1.0 contact admin@wati.io bearer abcdefghijklmnopqrstuvwxyz12345",
			},
			JsonPayload: models.JsonPayload{
				RequestID: "req-1",
				Message:   "safe message",
			},
		},
	})

	if strings.Contains(log.UserAgent, "admin@wati.io") {
		t.Fatalf("expected email to be redacted in user agent, got %q", log.UserAgent)
	}
	if strings.Contains(log.UserAgent, "abcdefghijklmnopqrstuvwxyz12345") {
		t.Fatalf("expected token to be redacted in user agent, got %q", log.UserAgent)
	}
	if !strings.Contains(log.UserAgent, "REDACTED_EMAIL") {
		t.Fatalf("expected REDACTED_EMAIL marker in user agent, got %q", log.UserAgent)
	}
	if !strings.Contains(log.UserAgent, "REDACTED_TOKEN") {
		t.Fatalf("expected REDACTED_TOKEN marker in user agent, got %q", log.UserAgent)
	}
}

func TestRedactURL_RedactsHostAndQueryValues(t *testing.T) {
	r := newPIIRedactor()
	got := r.RedactURL("https://live-server-74.wati.io/v1/tenant/600647?token=abc123&email=a@wati.io")

	if !strings.Contains(got, "REDACTED_HOST") {
		t.Fatalf("expected host redaction, got %q", got)
	}
	if strings.Contains(got, "abc123") || strings.Contains(got, "a@wati.io") {
		t.Fatalf("expected query values redacted, got %q", got)
	}
	if !strings.Contains(got, "token=REDACTED") || !strings.Contains(got, "email=REDACTED") {
		t.Fatalf("expected query markers to be redacted, got %q", got)
	}
}

func keys(m map[string]models.SanitizedBatch) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
