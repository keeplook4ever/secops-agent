package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"secops-agent/pkg/models"
)

// reportStore holds the in-memory report data loaded from disk at server startup.
type reportStore struct {
	report *models.IncidentReport
	audit  *AuditLogger
}

// handleListReports returns all tenant reports the caller is authorised to see.
//
//	GET /api/v1/reports
//
// Filtering rules (DESIGN.md Q3):
//
//	secops-admin       → all reports (tenant + platform)
//	tenant-admin       → only reports where tenant_id == claims.tenant_id
//	compliance-auditor → all reports, but PII fields double-redacted
//	engineer-readonly  → platform reports + de-identified tenant reports
func (s *reportStore) handleListReports(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "no claims in context")
		return
	}

	result := s.filterReport(claims, "")

	status := http.StatusOK
	s.audit.Log(AuditEntry{
		Role:     string(claims.Role),
		Subject:  claims.Sub,
		TenantID: claims.TenantID,
		Path:     r.URL.Path,
		Method:   r.Method,
		Status:   status,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}

// handleGetTenantReport returns the report for a specific tenant.
//
//	GET /api/v1/reports/{tenant_id}
func (s *reportStore) handleGetTenantReport(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "no claims in context")
		return
	}

	// Extract tenant_id from URL path: /api/v1/reports/{tenant_id}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/reports/"), "/")
	requestedTenantID := pathParts[0]
	if requestedTenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id is required in path")
		return
	}

	// RBAC enforcement: tenant-admin can only access own tenant.
	if claims.Role == RoleTenantAdmin && claims.TenantID != requestedTenantID {
		status := http.StatusForbidden
		s.audit.Log(AuditEntry{
			Role:     string(claims.Role),
			Subject:  claims.Sub,
			TenantID: claims.TenantID,
			Path:     r.URL.Path,
			Method:   r.Method,
			Status:   status,
		})
		writeError(w, status, "access denied: you can only access your own tenant's reports")
		return
	}

	result := s.filterReport(claims, requestedTenantID)

	// Check if tenant was found.
	if len(result.TenantReports) == 0 && result.PlatformReport == nil {
		status := http.StatusNotFound
		s.audit.Log(AuditEntry{
			Role:     string(claims.Role),
			Subject:  claims.Sub,
			TenantID: claims.TenantID,
			Path:     r.URL.Path,
			Method:   r.Method,
			Status:   status,
		})
		writeError(w, status, "no report found for tenant_id: "+requestedTenantID)
		return
	}

	status := http.StatusOK
	s.audit.Log(AuditEntry{
		Role:     string(claims.Role),
		Subject:  claims.Sub,
		TenantID: claims.TenantID,
		Path:     r.URL.Path,
		Method:   r.Method,
		Status:   status,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}

// filterReport applies RBAC filtering to the full report based on the caller's claims.
// If filterTenantID is non-empty, only that tenant is included.
func (s *reportStore) filterReport(claims *Claims, filterTenantID string) *models.IncidentReport {
	result := &models.IncidentReport{
		GeneratedAt: s.report.GeneratedAt,
		SourceFile:  s.report.SourceFile,
		TotalLogs:   s.report.TotalLogs,
		Summary:     s.report.Summary,
	}

	switch claims.Role {
	case RoleSecOpsAdmin:
		// Full access to everything.
		for _, tr := range s.report.TenantReports {
			if filterTenantID != "" && tr.TenantID != filterTenantID {
				continue
			}
			result.TenantReports = append(result.TenantReports, tr)
		}
		if filterTenantID == "" || filterTenantID == "platform" {
			result.PlatformReport = s.report.PlatformReport
		}

	case RoleTenantAdmin:
		// Only own tenant.
		for _, tr := range s.report.TenantReports {
			if tr.TenantID == claims.TenantID {
				if filterTenantID != "" && tr.TenantID != filterTenantID {
					continue
				}
				result.TenantReports = append(result.TenantReports, tr)
			}
		}
		// No platform report access.

	case RoleComplianceAuditor:
		// All tenants but with double-redacted PII fields.
		for _, tr := range s.report.TenantReports {
			if filterTenantID != "" && tr.TenantID != filterTenantID {
				continue
			}
			redacted := redactTenantReport(tr)
			result.TenantReports = append(result.TenantReports, redacted)
		}
		if filterTenantID == "" || filterTenantID == "platform" {
			result.PlatformReport = s.report.PlatformReport
		}

	case RoleEngineerReadonly:
		// Platform + de-identified tenant reports.
		for _, tr := range s.report.TenantReports {
			if filterTenantID != "" && tr.TenantID != filterTenantID {
				continue
			}
			deidentified := deidentifyTenantReport(tr)
			result.TenantReports = append(result.TenantReports, deidentified)
		}
		if filterTenantID == "" || filterTenantID == "platform" {
			result.PlatformReport = s.report.PlatformReport
		}
	}

	return result
}

// redactTenantReport strips PII-adjacent fields for compliance-auditor role.
// Keeps SOC 2 control mappings and severity but removes descriptions that
// might contain reconstructable context.
func redactTenantReport(tr models.TenantReport) models.TenantReport {
	redacted := tr
	redacted.TenantID = "[REDACTED]"
	findings := make([]models.LLMFinding, len(tr.Findings))
	for i, f := range tr.Findings {
		findings[i] = f
		findings[i].Remediation = "[REDACTED_FOR_COMPLIANCE]"
	}
	redacted.Findings = findings
	return redacted
}

// deidentifyTenantReport removes tenant-identifying information for
// engineer-readonly role. They can see attack patterns and SOC 2 mappings
// for learning, but not which tenant was affected.
func deidentifyTenantReport(tr models.TenantReport) models.TenantReport {
	deidentified := tr
	deidentified.TenantID = ""
	deidentified.TenantKey = "[DE-IDENTIFIED]"
	return deidentified
}
