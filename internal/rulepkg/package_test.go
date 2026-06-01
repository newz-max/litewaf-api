package rulepkg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"litewaf-api/internal/model"
	"litewaf-api/internal/store"
)

func TestParseValidPackage(t *testing.T) {
	payload := testPackagePayload(t, "community-baseline", "v1", []map[string]any{
		{
			"id":         "xss-query",
			"name":       "Community XSS",
			"type":       "xss",
			"target":     "args",
			"action":     "block",
			"expression": "(?i)<script",
			"score":      80,
		},
	})
	pkg, invalid := Parse(payload)
	if len(invalid) != 0 {
		t.Fatalf("expected valid package, got invalid=%+v", invalid)
	}
	if pkg.Metadata.ID != "community-baseline" || pkg.Metadata.SignatureStatus != SignatureUnsigned {
		t.Fatalf("unexpected metadata: %+v", pkg.Metadata)
	}
	if len(pkg.Rules) != 1 || pkg.Rules[0].PackageRuleID != "xss-query" {
		t.Fatalf("unexpected rules: %+v", pkg.Rules)
	}
}

func TestParseRejectsInvalidPackageRules(t *testing.T) {
	payload := testPackagePayload(t, "bad-package", "v1", []map[string]any{
		{"id": "dup", "name": "One", "type": "xss", "target": "args", "action": "block", "expression": "(?i)<script"},
		{"id": "dup", "name": "Two", "type": "xss", "target": "args", "action": "block", "expression": "(?i)<script"},
		{"id": "broken", "name": "Broken", "type": "xss", "target": "args", "action": "block", "expression": "("},
	})
	_, invalid := Parse(payload)
	if len(invalid) != 2 {
		t.Fatalf("expected duplicate and invalid expression, got %+v", invalid)
	}
}

func TestPreviewAndImportAreDeterministic(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	payload := testPackagePayload(t, "community-baseline", "v1", []map[string]any{
		{"id": "xss-query", "name": "Community XSS", "type": "xss", "target": "args", "action": "block", "expression": "(?i)<script", "score": 80},
	})
	preview, err := Preview(ctx, dataStore, payload)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(preview.Added) != 1 || len(preview.Changed) != 0 || len(preview.Skipped) != 0 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	result, err := Import(ctx, dataStore, payload)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(result.Imported) != 1 {
		t.Fatalf("expected one imported rule, got %+v", result)
	}
	second, err := Preview(ctx, dataStore, payload)
	if err != nil {
		t.Fatalf("second preview: %v", err)
	}
	if len(second.Skipped) != 1 || len(second.Added) != 0 {
		t.Fatalf("expected deterministic skip, got %+v", second)
	}
}

func TestRuleTestMatchesAndRejectsSensitiveSamples(t *testing.T) {
	rule := model.Rule{
		ID: 1, Name: "XSS", Type: "xss", Target: "args", Action: "block", Expression: "(?i)<script", Score: 80,
	}
	result, err := TestRule(rule, model.RuleTestSample{
		Method: "GET",
		Path:   "/search",
		Query:  map[string]string{"q": "<script>alert(1)</script>"},
	})
	if err != nil {
		t.Fatalf("test rule: %v", err)
	}
	if !result.Matched || result.Status != TestPassed {
		t.Fatalf("expected match, got %+v", result)
	}
	_, err = TestRule(rule, model.RuleTestSample{
		Headers: map[string]string{"Authorization": "secret"},
	})
	if err == nil || !strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("expected sensitive header rejection, got %v", err)
	}
}

func testPackagePayload(t *testing.T, id string, version string, rules []map[string]any) []byte {
	t.Helper()
	payload := map[string]any{
		"id":            id,
		"name":          id,
		"version":       version,
		"author":        "LiteWaf Community",
		"license":       "MIT",
		"compatibility": Compatibility,
		"defaults": map[string]any{
			"enabled":       false,
			"review_status": ReviewPending,
		},
		"rules": rules,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal package: %v", err)
	}
	return data
}
