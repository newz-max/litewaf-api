package rulepkg

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestParseCatalogSyncPreviewUpdateAndExport(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	initial := testPackagePayload(t, "community-baseline", "v1", []map[string]any{
		{"id": "xss-query", "name": "Community XSS", "type": "xss", "target": "args", "action": "block", "expression": "(?i)<script", "score": 80},
	})
	catalogPath := writeCatalog(t, "community-baseline", "v1", initial, "")
	source, err := dataStore.CreateRuleCatalogSource(ctx, model.RuleCatalogSource{
		Name:       "Local community",
		Source:     catalogPath,
		Enabled:    true,
		TimeoutSec: 5,
		Status:     CatalogStatusNeverSynced,
	})
	if err != nil {
		t.Fatalf("create catalog: %v", err)
	}
	items, err := SyncCatalog(ctx, dataStore, source)
	if err != nil {
		t.Fatalf("sync catalog: %v", err)
	}
	if len(items) != 1 || items[0].PackageID != "community-baseline" {
		t.Fatalf("unexpected catalog items: %+v", items)
	}
	preview, err := RemotePreview(ctx, dataStore, items[0])
	if err != nil {
		t.Fatalf("remote preview: %v", err)
	}
	if len(preview.Added) != 1 || preview.SourceCatalogID == "" {
		t.Fatalf("unexpected remote preview: %+v", preview)
	}
	if _, err := ApplyUpdate(ctx, dataStore, items[0]); err != nil {
		t.Fatalf("apply first import: %v", err)
	}
	updated := testPackagePayload(t, "community-baseline", "v2", []map[string]any{
		{"id": "xss-query", "name": "Community XSS v2", "type": "xss", "target": "args", "action": "block", "expression": "(?i)<script|javascript:", "score": 85},
		{"id": "rce-query", "name": "Community RCE", "type": "rce", "target": "args", "action": "block", "expression": "(?i)wget|curl", "score": 90},
	})
	catalogPath = writeCatalog(t, "community-baseline", "v2", updated, catalogPath)
	source.Source = catalogPath
	source, _ = dataStore.UpdateRuleCatalogSource(ctx, source.ID, source)
	items, err = SyncCatalog(ctx, dataStore, source)
	if err != nil {
		t.Fatalf("sync updated catalog: %v", err)
	}
	updatePreview, err := UpdatePreview(ctx, dataStore, items[0])
	if err != nil {
		t.Fatalf("update preview: %v", err)
	}
	if len(updatePreview.Changed) != 1 || len(updatePreview.Added) != 1 {
		t.Fatalf("unexpected update preview: %+v", updatePreview)
	}
	rules, _ := dataStore.ListRules(ctx)
	var importedID int64
	for _, rule := range rules {
		if rule.PackageID == "community-baseline" {
			importedID = rule.ID
			break
		}
	}
	exportPreview, err := ExportPreview(ctx, dataStore, model.RulePackageExportRequest{
		PackageID: "exported-community",
		Name:      "Exported Community",
		Version:   "v1",
		Author:    "Tester",
		License:   "MIT",
		RuleIDs:   []int64{importedID},
	})
	if err != nil {
		t.Fatalf("export preview: %v", err)
	}
	if len(exportPreview.SelectedRules) != 1 || len(exportPreview.Invalid) != 0 {
		t.Fatalf("unexpected export preview: %+v", exportPreview)
	}
	artifact, err := ExportArtifact(ctx, dataStore, model.RulePackageExportRequest{
		PackageID: "exported-community",
		Name:      "Exported Community",
		Version:   "v1",
		Author:    "Tester",
		License:   "MIT",
		RuleIDs:   []int64{importedID},
	})
	if err != nil {
		t.Fatalf("export artifact: %v", err)
	}
	if artifact.Checksum == "" || strings.Contains(strings.ToLower(artifact.Artifact), "authorization") {
		t.Fatalf("unexpected artifact: %+v", artifact)
	}
}

func TestTrustKeySignatureStatuses(t *testing.T) {
	expired := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if status := SignatureStatus(model.RulePackageSignature{KeyID: "unknown", Checksum: "abc", Signature: "abc"}, "abc", []model.RuleTrustKey{}); status != SignatureUntrustedKey {
		t.Fatalf("expected untrusted key, got %s", status)
	}
	if status := SignatureStatus(model.RulePackageSignature{KeyID: "revoked", Checksum: "abc", Signature: "abc"}, "abc", []model.RuleTrustKey{{KeyID: "revoked", Enabled: true, Revoked: true}}); status != SignatureRevokedKey {
		t.Fatalf("expected revoked key, got %s", status)
	}
	if status := SignatureStatus(model.RulePackageSignature{KeyID: "expired", Checksum: "abc", Signature: "abc", ExpiresAt: expired}, "abc", []model.RuleTrustKey{{KeyID: "expired", Enabled: true}}); status != SignatureExpired {
		t.Fatalf("expected expired signature, got %s", status)
	}
	if status := SignatureStatus(model.RulePackageSignature{KeyID: "trusted", Checksum: "abc", Signature: "abc"}, "abc", []model.RuleTrustKey{{KeyID: "trusted", Enabled: true}}); status != SignatureVerified {
		t.Fatalf("expected verified, got %s", status)
	}
}

func TestPreviewAndImportApplyTrustKeys(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	payload := []byte(`{
		"id":"signed-community",
		"name":"Signed Community",
		"version":"v1",
		"author":"LiteWaf Community",
		"license":"MIT",
		"compatibility":"litewaf-rule-package-v1",
		"checksum":"abc",
		"signature":{"key_id":"revoked-key","checksum":"abc","signature":"abc"},
		"defaults":{"enabled":false,"review_status":"pending-review"},
		"rules":[{"id":"xss-query","name":"Signed XSS","type":"xss","target":"args","action":"block","expression":"(?i)<script","score":80}]
	}`)
	trustKeys := []model.RuleTrustKey{{KeyID: "revoked-key", Algorithm: "local", Enabled: true, Revoked: true}}
	preview, err := PreviewWithTrustKeys(ctx, dataStore, payload, trustKeys)
	if err != nil {
		t.Fatalf("preview with trust keys: %v", err)
	}
	if preview.Package.SignatureStatus != SignatureRevokedKey || preview.Added[0].SignatureStatus != SignatureRevokedKey {
		t.Fatalf("expected revoked signature status, got %+v", preview)
	}
	result, err := ImportWithTrustKeys(ctx, dataStore, payload, trustKeys)
	if err != nil {
		t.Fatalf("import with trust keys: %v", err)
	}
	if len(result.Imported) != 1 || result.Imported[0].SignatureStatus != SignatureRevokedKey {
		t.Fatalf("expected imported rule to preserve revoked status, got %+v", result)
	}
}

func writeCatalog(t *testing.T, packageID string, version string, packageData []byte, reusePath string) string {
	t.Helper()
	path := reusePath
	if path == "" {
		path = filepath.Join(t.TempDir(), "catalog.json")
	}
	sum := checksumBytes(packageData)
	payload := map[string]any{
		"schema_version": "litewaf-rule-catalog-v1",
		"packages": []map[string]any{
			{
				"id":            packageID,
				"name":          packageID,
				"version":       version,
				"compatibility": Compatibility,
				"checksum":      sum,
				"updated_at":    time.Now().UTC().Format(time.RFC3339),
				"package":       json.RawMessage(packageData),
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	return path
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
