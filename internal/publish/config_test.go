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
	var decoded GatewayConfig
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("payload json: %v", err)
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
