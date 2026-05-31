package publish

import (
	"context"
	"encoding/json"
	"testing"

	"litewaf-api/internal/model"
	"litewaf-api/internal/store"
)

func TestGenerateGatewayConfig(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()

	site, err := dataStore.CreateSite(ctx, model.Site{
		Name:     "Example",
		Host:     "example.local",
		Upstream: "http://upstream",
		Mode:     "protect",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("create site: %v", err)
	}

	rules, err := dataStore.ListRules(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("expected baseline rules")
	}
	foundRCE := false
	for _, rule := range rules {
		if rule.Type == "rce" {
			foundRCE = true
			break
		}
	}
	if !foundRCE {
		t.Fatal("expected baseline RCE rule")
	}

	_, err = dataStore.CreatePolicy(ctx, model.Policy{
		Name:          "Default",
		RiskThreshold: 100,
		DefaultAction: "block",
		Enabled:       true,
		SiteIDs:       []int64{site.ID},
		RuleIDs:       []int64{rules[0].ID},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	config, payload, checksum, err := Generate(ctx, dataStore, "ruleset-0001")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if checksum == "" {
		t.Fatal("expected checksum")
	}
	if len(config.Sites) != 1 {
		t.Fatalf("expected 1 site, got %d", len(config.Sites))
	}
	if len(config.Sites[0].Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(config.Sites[0].Rules))
	}
	if config.Sites[0].Policy.RiskThreshold != 100 {
		t.Fatalf("expected published policy threshold, got %+v", config.Sites[0].Policy)
	}
	var decoded GatewayConfig
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("payload json: %v", err)
	}
}

func TestGenerateExtendedGatewayConfigIncludesAdvancedProtection(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	site, err := dataStore.CreateSite(ctx, model.Site{
		Name: "Advanced", Host: "advanced.local", Upstream: "http://upstream", Mode: "protect", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	rule, err := dataStore.CreateRule(ctx, model.Rule{
		Name: "JSON XSS", Type: "xss", Target: "body_json", Action: "log-only", Expression: "(?i)<script", Score: 60, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	_, err = dataStore.CreatePolicy(ctx, model.Policy{
		Name: "Advanced", RiskThreshold: 120, DefaultAction: "block",
		NormalizationEnabled: true, NormalizationDecodePasses: 2, NormalizationMaxValueBytes: 4096,
		BodyInspectionEnabled: true, BodyInspectionContentTypes: []string{"application/json"}, BodyInspectionPathPrefixes: []string{"/api"}, BodyInspectionMaxBytes: 65536, OversizedBodyAction: "log-only",
		UploadInspectionEnabled: true, UploadMaxBytes: 1024, UploadSizeAction: "block",
		DynamicBanEnabled: true, DynamicBanDurationSec: 300, DynamicBanScoreThreshold: 200, DynamicBanTriggerCount: 3, DynamicBanWindowSec: 60,
		Enabled: true, SiteIDs: []int64{site.ID}, RuleIDs: []int64{rule.ID},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	_, err = dataStore.CreateRateLimitRule(ctx, model.RateLimitRule{
		Name: "CC", Scope: "ip", Threshold: 10, WindowSec: 60, Action: "block", BanDuration: 300, ViolationThreshold: 3, ViolationWindowSec: 120, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create rate limit: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-advanced")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if !config.Sites[0].Policy.BodyInspectionEnabled || !config.Sites[0].Policy.DynamicBanEnabled {
		t.Fatalf("expected advanced policy settings: %+v", config.Sites[0].Policy)
	}
	if config.Sites[0].Rules[0].Target != "body_json" {
		t.Fatalf("expected advanced rule target, got %+v", config.Sites[0].Rules[0])
	}
	if config.RateLimits[0].ViolationThreshold != 3 {
		t.Fatalf("expected repeated violation settings, got %+v", config.RateLimits[0])
	}
}

func TestGenerateGatewayConfigEmptyState(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()

	config, _, _, err := Generate(ctx, dataStore, "ruleset-0001")
	if err != nil {
		t.Fatalf("generate empty: %v", err)
	}
	if len(config.Sites) != 0 {
		t.Fatalf("expected no sites, got %d", len(config.Sites))
	}
}
