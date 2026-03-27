package sanitizer

import (
	"github.com/wati/secops-agent/pkg/models"
)

// Sanitizer is the public interface for the sanitization layer.
// Implementations must be safe for concurrent use.
type Sanitizer interface {
	// Sanitize converts a ClassifiedLog into a SanitizedLog. All PII and
	// secret values are replaced with structured placeholders, and any
	// prompt-injection patterns found in free-text fields are neutralised
	// before the data can reach an LLM.
	Sanitize(log models.ClassifiedLog) models.SanitizedLog

	// GroupIntoBatches groups a slice of SanitizedLogs by TenantKey, producing
	// one SanitizedBatch per unique key. PLATFORM logs form their own batch.
	GroupIntoBatches(logs []models.SanitizedLog) []models.SanitizedBatch
}

// DefaultSanitizer is the production implementation of Sanitizer.
type DefaultSanitizer struct {
	pii       *piiRedactor
	injection *injectionDetector
}

// New creates a DefaultSanitizer. A single instance should be reused across
// the pipeline run so that the tenant ID mapping is consistent.
func New() *DefaultSanitizer {
	return &DefaultSanitizer{
		pii:       newPIIRedactor(),
		injection: newInjectionDetector(),
	}
}

// Sanitize implements Sanitizer.
func (s *DefaultSanitizer) Sanitize(cl models.ClassifiedLog) models.SanitizedLog {
	l := cl.Raw

	// --- Tenant mapping ---
	tenantKey := s.pii.MapTenant(cl.Scope, cl.TenantID)

	// --- Free-text fields: injection scan first, then PII redaction ---
	msgScan := s.injection.Scan(l.JsonPayload.Message)
	var injectionDetected bool
	var injectionPatterns []string
	sanitizedMessage := msgScan.SanitizedValue
	if msgScan.Detected {
		injectionDetected = true
		injectionPatterns = append(injectionPatterns, msgScan.MatchedPatterns...)
	} else {
		// No injection found; still redact PII from the message text.
		sanitizedMessage = s.pii.RedactMessage(sanitizedMessage)
	}

	// UserAgent may also carry injection payloads (rare but possible).
	uaScan := s.injection.Scan(l.HttpRequest.UserAgent)
	sanitizedUA := uaScan.SanitizedValue
	if uaScan.Detected {
		injectionDetected = true
		injectionPatterns = append(injectionPatterns, uaScan.MatchedPatterns...)
	} else {
		sanitizedUA = s.pii.RedactMessage(sanitizedUA)
	}

	return models.SanitizedLog{
		OriginalRequestID: l.JsonPayload.RequestID,
		Scope:             cl.Scope,
		TenantKey:         tenantKey,

		Timestamp:  l.Timestamp,
		Severity:   l.Severity,
		LogName:    l.LogName,
		Method:     l.HttpRequest.RequestMethod,
		Status:     l.HttpRequest.Status,
		Latency:    l.HttpRequest.Latency,
		UserAgent:  sanitizedUA,
		RemoteIP:   s.pii.RedactIP(l.HttpRequest.RemoteIP),
		RequestURL: s.pii.RedactURL(l.HttpRequest.RequestURL),

		UserEmail:    s.pii.RedactEmail(l.JsonPayload.UserEmail),
		DatabaseName: s.pii.RedactDatabase(l.JsonPayload.DatabaseName),
		Message:      sanitizedMessage,

		InjectionDetected: injectionDetected,
		InjectionPatterns: injectionPatterns,
	}
}

// GroupIntoBatches implements Sanitizer.
// Each unique TenantKey gets its own batch, ensuring no LLM call ever
// contains data from more than one tenant or mixes PLATFORM with TENANT data.
func (s *DefaultSanitizer) GroupIntoBatches(logs []models.SanitizedLog) []models.SanitizedBatch {
	order := make([]string, 0)
	index := make(map[string]int)

	for _, l := range logs {
		key := l.TenantKey
		if _, seen := index[key]; !seen {
			index[key] = len(order)
			order = append(order, key)
		}
	}

	batches := make([]models.SanitizedBatch, len(order))
	for i, key := range order {
		scope := models.ScopeTenant
		if key == "PLATFORM" {
			scope = models.ScopePlatform
		}
		batches[i] = models.SanitizedBatch{TenantKey: key, Scope: scope}
	}

	for _, l := range logs {
		i := index[l.TenantKey]
		batches[i].Logs = append(batches[i].Logs, l)
	}

	return batches
}
