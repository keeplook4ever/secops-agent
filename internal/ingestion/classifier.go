package ingestion

import (
	"strings"

	"secops-agent/pkg/models"
)

// platformLogNames contains substrings that identify infrastructure-level logs.
// These logs originate from GKE audit, IAM activity, etc., and intentionally
// have no tenant_id.
var platformLogNames = []string{
	"cloudaudit.googleapis.com",
	"activity",
	"data_access",
	"system_event",
}

// Classifier assigns a LogScope to each raw log entry.
type Classifier struct{}

// NewClassifier creates a Classifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

// Classify adds scope and tenant metadata to each raw log entry.
//
// Design rationale (from DESIGN.md, Question 1):
//   - GKE audit / IAM logs are PLATFORM-scoped; an empty tenant_id is
//     expected and correct. Discarding them would silently hide the most
//     critical platform-level security events (e.g. unauthorized kubectl exec).
//   - API gateway logs are TENANT-scoped; a missing tenant_id is anomalous
//     and flagged as TENANT_ID_MISSING but still retained for analysis.
func (c *Classifier) Classify(logs []models.RawLog) []models.ClassifiedLog {
	out := make([]models.ClassifiedLog, 0, len(logs))
	for _, l := range logs {
		scope := c.scopeOf(l)
		out = append(out, models.ClassifiedLog{
			Raw:      l,
			Scope:    scope,
			TenantID: l.JsonPayload.TenantID,
		})
	}
	return out
}

func (c *Classifier) scopeOf(l models.RawLog) models.LogScope {
	lower := strings.ToLower(l.LogName)
	for _, marker := range platformLogNames {
		if strings.Contains(lower, marker) {
			return models.ScopePlatform
		}
	}
	return models.ScopeTenant
}
