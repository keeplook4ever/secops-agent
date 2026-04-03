package validator

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"secops-agent/pkg/models"
)

// validSeverities is the set of severity strings we accept from the LLM.
var validSeverities = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
	"INFO":     true,
}

// validSOC2 matches well-formed SOC 2 Trust Service Criteria identifiers.
var validSOC2 = regexp.MustCompile(`^(CC|A|PI|C|P)\d+\.\d+$`)

// cvePattern matches the standard CVE-YYYY-NNNNN format.
var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Validator parses and validates the raw JSON bytes returned by an LLM call.
// It enforces the schema, rejects suspicious CVEs, and flags low-confidence
// responses — all without trusting that the LLM output is well-formed.
type Validator struct {
	confidenceThreshold float64
}

// New creates a Validator. threshold is the minimum acceptable confidence_score
// (typically 0.7). Findings below the threshold are flagged but not discarded.
func New(confidenceThreshold float64) *Validator {
	return &Validator{confidenceThreshold: confidenceThreshold}
}

// ValidationResult is the outcome of validating a single LLM batch response.
type ValidationResult struct {
	Response        models.LLMBatchResponse
	Status          models.ValidationStatus
	Notes           []string
	LowConfidence   []string // request_ids with confidence < threshold
	RejectedCVEs    map[string][]string // request_id → bad CVEs stripped
}

// Validate parses rawJSON and runs all validation checks.
// It never returns an error for soft failures (low confidence, stripped CVEs).
// Hard failures (schema mismatch, unparseable JSON) return a non-nil error.
func (v *Validator) Validate(rawJSON []byte, expectedTenantKey string, expectedRequestIDs []string) (*ValidationResult, error) {
	result := &ValidationResult{
		Status:       models.ValidationOK,
		RejectedCVEs: make(map[string][]string),
	}

	// --- 1. Parse JSON ---
	candidate := extractJSONObject(rawJSON)
	if err := json.Unmarshal(candidate, &result.Response); err != nil {
		return nil, fmt.Errorf("validator: unmarshal: %w", err)
	}

	// --- 2. Tenant key check ---
	if result.Response.TenantKey != expectedTenantKey {
		note := fmt.Sprintf("tenant_key mismatch: got %q, expected %q",
			result.Response.TenantKey, expectedTenantKey)
		result.Notes = append(result.Notes, note)
		result.Status = models.ValidationSchemaMismatch
		// Force the correct key — we know which batch this came from.
		result.Response.TenantKey = expectedTenantKey
	}

	// --- 3. Per-finding validation ---
	for i := range result.Response.Findings {
		f := &result.Response.Findings[i]

		// 3a. Required fields
		if f.RequestID == "" {
			result.Notes = append(result.Notes, fmt.Sprintf("finding[%d]: missing request_id", i))
			result.Status = models.ValidationSchemaMismatch
		}

		// 3b. Severity
		if !validSeverities[strings.ToUpper(f.Severity)] {
			note := fmt.Sprintf("%s: invalid severity %q", f.RequestID, f.Severity)
			result.Notes = append(result.Notes, note)
			result.Status = models.ValidationSchemaMismatch
		} else {
			f.Severity = strings.ToUpper(f.Severity)
		}

		// 3c. Confidence score
		if f.ConfidenceScore < v.confidenceThreshold {
			result.LowConfidence = append(result.LowConfidence, f.RequestID)
			if result.Status == models.ValidationOK {
				result.Status = models.ValidationLowConfidence
			}
		}

		// 3d. CVE validation — strip any CVE that doesn't match the standard format.
		// We do not call an external database; format validation catches hallucinated
		// CVEs like "CVE-2026-99999" or free-form strings.
		var cleanCVEs []string
		for _, cve := range f.CVEs {
			cve = strings.TrimSpace(cve)
			if cve == "" {
				continue
			}
			if !cvePattern.MatchString(cve) {
				result.RejectedCVEs[f.RequestID] = append(result.RejectedCVEs[f.RequestID], cve)
				if result.Status == models.ValidationOK {
					result.Status = models.ValidationInvalidCVE
				}
				note := fmt.Sprintf("%s: stripped malformed CVE %q", f.RequestID, cve)
				result.Notes = append(result.Notes, note)
				continue
			}
			cleanCVEs = append(cleanCVEs, cve)
		}
		f.CVEs = cleanCVEs

		// 3e. SOC 2 control format check
		for j, ctrl := range f.SOC2Controls {
			if !validSOC2.MatchString(ctrl) {
				result.Notes = append(result.Notes,
					fmt.Sprintf("%s: suspicious SOC2 control at index %d: %q", f.RequestID, j, ctrl))
			}
		}
	}

	// --- 4. Batch completeness checks ---
	if len(result.Response.Findings) != len(expectedRequestIDs) {
		result.Status = models.ValidationSchemaMismatch
		result.Notes = append(result.Notes,
			fmt.Sprintf("finding count mismatch: got %d, expected %d",
				len(result.Response.Findings), len(expectedRequestIDs)))
	}

	expectedSet := make(map[string]bool, len(expectedRequestIDs))
	for _, id := range expectedRequestIDs {
		if id == "" {
			continue
		}
		expectedSet[id] = true
	}

	seen := make(map[string]int, len(result.Response.Findings))
	for _, f := range result.Response.Findings {
		if f.RequestID == "" {
			continue
		}
		seen[f.RequestID]++
	}

	for reqID, count := range seen {
		if count > 1 {
			result.Status = models.ValidationSchemaMismatch
			result.Notes = append(result.Notes,
				fmt.Sprintf("duplicate request_id in findings: %s (count=%d)", reqID, count))
		}
		if !expectedSet[reqID] {
			result.Status = models.ValidationSchemaMismatch
			result.Notes = append(result.Notes,
				fmt.Sprintf("unexpected request_id in findings: %s", reqID))
		}
	}
	for reqID := range expectedSet {
		if seen[reqID] == 0 {
			result.Status = models.ValidationSchemaMismatch
			result.Notes = append(result.Notes,
				fmt.Sprintf("missing request_id in findings: %s", reqID))
		}
	}

	if len(result.LowConfidence) > 0 {
		result.Notes = append(result.Notes,
			fmt.Sprintf("low confidence findings: %s", strings.Join(result.LowConfidence, ", ")))
	}

	return result, nil
}

// extractJSONObject normalizes common LLM wrappers (markdown code fences, prose)
// and returns the first top-level JSON object segment.
func extractJSONObject(raw []byte) []byte {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return raw
	}

	if strings.HasPrefix(s, "```") {
		lines := strings.Split(s, "\n")
		if len(lines) >= 2 {
			lines = lines[1:]
			for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "```" {
				lines = lines[:len(lines)-1]
			}
			s = strings.TrimSpace(strings.Join(lines, "\n"))
		}
	}

	start := strings.Index(s, "{")
	if start == -1 {
		return []byte(s)
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return []byte(strings.TrimSpace(s[start : i+1]))
			}
		}
	}
	return []byte(strings.TrimSpace(s[start:]))
}
