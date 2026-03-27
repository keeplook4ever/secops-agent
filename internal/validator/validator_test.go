package validator

import (
	"strings"
	"testing"

	"github.com/wati/secops-agent/pkg/models"
)

func TestValidate_FindingCountMismatch(t *testing.T) {
	v := New(0.7)
	raw := []byte(`{
		"tenant_key":"TENANT_ID_1",
		"findings":[
			{
				"request_id":"req-1",
				"severity":"HIGH",
				"attack_pattern":"BruteForce",
				"description":"desc",
				"soc2_controls":["CC6.1"],
				"cves":[],
				"confidence_score":0.92,
				"remediation":"remediate"
			}
		]
	}`)

	res, err := v.Validate(raw, "TENANT_ID_1", []string{"req-1", "req-2"})
	if err != nil {
		t.Fatalf("expected no hard error, got %v", err)
	}
	if res.Status != models.ValidationSchemaMismatch {
		t.Fatalf("expected schema mismatch, got %s", res.Status)
	}
	if !containsNote(res.Notes, "finding count mismatch") {
		t.Fatalf("expected finding count mismatch note, got %v", res.Notes)
	}
	if !containsNote(res.Notes, "missing request_id in findings: req-2") {
		t.Fatalf("expected missing request note, got %v", res.Notes)
	}
}

func TestValidate_RequestIDSetMismatch(t *testing.T) {
	v := New(0.7)
	raw := []byte(`{
		"tenant_key":"TENANT_ID_1",
		"findings":[
			{
				"request_id":"req-1",
				"severity":"HIGH",
				"attack_pattern":"BruteForce",
				"description":"desc-1",
				"soc2_controls":["CC6.1"],
				"cves":[],
				"confidence_score":0.9,
				"remediation":"remediate"
			},
			{
				"request_id":"req-1",
				"severity":"MEDIUM",
				"attack_pattern":"Reconnaissance",
				"description":"desc-2",
				"soc2_controls":["CC7.2"],
				"cves":[],
				"confidence_score":0.9,
				"remediation":"remediate"
			},
			{
				"request_id":"req-3",
				"severity":"LOW",
				"attack_pattern":"Normal",
				"description":"desc-3",
				"soc2_controls":["CC7.3"],
				"cves":[],
				"confidence_score":0.9,
				"remediation":"remediate"
			}
		]
	}`)

	res, err := v.Validate(raw, "TENANT_ID_1", []string{"req-1", "req-2"})
	if err != nil {
		t.Fatalf("expected no hard error, got %v", err)
	}
	if res.Status != models.ValidationSchemaMismatch {
		t.Fatalf("expected schema mismatch, got %s", res.Status)
	}
	if !containsNote(res.Notes, "duplicate request_id in findings: req-1") {
		t.Fatalf("expected duplicate request note, got %v", res.Notes)
	}
	if !containsNote(res.Notes, "unexpected request_id in findings: req-3") {
		t.Fatalf("expected unexpected request note, got %v", res.Notes)
	}
	if !containsNote(res.Notes, "missing request_id in findings: req-2") {
		t.Fatalf("expected missing request note, got %v", res.Notes)
	}
}

func TestValidate_AcceptsMarkdownFencedJSON(t *testing.T) {
	v := New(0.7)
	raw := []byte("```json\n{\n  \"tenant_key\": \"TENANT_ID_1\",\n  \"findings\": [\n    {\n      \"request_id\": \"req-1\",\n      \"severity\": \"HIGH\",\n      \"attack_pattern\": \"BruteForce\",\n      \"description\": \"desc\",\n      \"soc2_controls\": [\"CC6.1\"],\n      \"cves\": [],\n      \"confidence_score\": 0.95,\n      \"remediation\": \"remediate\"\n    }\n  ]\n}\n```")

	res, err := v.Validate(raw, "TENANT_ID_1", []string{"req-1"})
	if err != nil {
		t.Fatalf("expected fenced JSON to be parsed, got error: %v", err)
	}
	if res.Status != models.ValidationOK {
		t.Fatalf("expected validation OK, got %s with notes %v", res.Status, res.Notes)
	}
}

func containsNote(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}
