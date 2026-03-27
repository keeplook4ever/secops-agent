package sanitizer

import (
	"regexp"
)

// InjectionPattern describes a single prompt-injection detection rule.
type InjectionPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// injectionRules is the ordered list of patterns applied to every free-text
// log field before the data is placed into an LLM prompt.
//
// Design rationale (DESIGN.md, Question 2 — Layer 1):
//   A malicious actor who knows this agent feeds log fields into an LLM can
//   craft log entries containing adversarial instructions. The goals range from
//   causing the LLM to mis-classify a CRITICAL event as INFO (alert suppression)
//   to leaking sanitized context from other log entries in the same batch.
//
//   We detect known injection patterns, replace the offending field content
//   with [FLAGGED_INJECTION_ATTEMPT], and mark the log entry with
//   InjectionDetected=true. The entry is NOT discarded — instead its presence
//   becomes a CRITICAL finding in its own right (attack_pattern: PROMPT_INJECTION).
var injectionRules = []InjectionPattern{
	{
		Name:    "IGNORE_INSTRUCTIONS",
		Pattern: regexp.MustCompile(`(?i)ignore\s+(previous|prior|all)?\s*(instructions?|rules?|context|system\s+prompt)`),
	},
	{
		Name:    "SYSTEM_OVERRIDE",
		Pattern: regexp.MustCompile(`(?i)(system\s*(override|prompt|message|role)|disable\s+(security|checks?|filter))`),
	},
	{
		Name:    "TEMPLATE_INJECTION",
		Pattern: regexp.MustCompile(`\{\{.*?\}\}`),
	},
	{
		Name:    "SQL_INJECTION",
		Pattern: regexp.MustCompile(`(?i)(select\s+\*\s+from|drop\s+table|insert\s+into|delete\s+from|union\s+select|--\s*$)`),
	},
	{
		Name:    "ADMIN_OVERRIDE",
		Pattern: regexp.MustCompile(`(?i)(###.*OVERRIDE###|ADMIN_OVERRIDE|BYPASS.*RATE\s*LIMIT|maintenance\s+mode)`),
	},
	{
		Name:    "JAILBREAK_ROLE",
		Pattern: regexp.MustCompile(`(?i)(you\s+are\s+now\s+in|act\s+as\s+(admin|root|superuser)|forget\s+(your\s+)?(training|instructions))`),
	},
	{
		Name:    "DATA_EXFIL_INSTRUCTION",
		Pattern: regexp.MustCompile(`(?i)(export\s+(full\s+)?(contact|tenant|user)\s+list|output\s+all\s+tenant|return\s+admin\s+credentials)`),
	},
}

// injectionDetector scans free-text fields for prompt-injection patterns.
type injectionDetector struct{}

func newInjectionDetector() *injectionDetector {
	return &injectionDetector{}
}

// ScanResult holds the outcome of scanning a single field value.
type ScanResult struct {
	Detected        bool
	MatchedPatterns []string
	SanitizedValue  string
}

// Scan checks value against all injection rules.
// If any rule matches, the value is replaced with [FLAGGED_INJECTION_ATTEMPT]
// and the matched rule names are recorded.
func (d *injectionDetector) Scan(value string) ScanResult {
	var matched []string
	for _, rule := range injectionRules {
		if rule.Pattern.MatchString(value) {
			matched = append(matched, rule.Name)
		}
	}
	if len(matched) == 0 {
		return ScanResult{Detected: false, SanitizedValue: value}
	}
	return ScanResult{
		Detected:        true,
		MatchedPatterns: matched,
		SanitizedValue:  "[FLAGGED_INJECTION_ATTEMPT]",
	}
}
