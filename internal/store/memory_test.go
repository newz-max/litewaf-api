package store

import (
	"context"
	"testing"

	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
)

func TestMemoryStoreSiteCreateAndList(t *testing.T) {
	ctx := context.Background()
	dataStore := NewMemoryStore()

	sites, err := dataStore.ListSites(ctx)
	if err != nil {
		t.Fatalf("list empty sites: %v", err)
	}
	if len(sites) != 0 {
		t.Fatalf("expected empty sites, got %d", len(sites))
	}

	created, err := dataStore.CreateSite(ctx, model.Site{
		Name:     "Example",
		Host:     "example.test",
		Upstream: "http://upstream:8080",
		Mode:     "protect",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected site id")
	}

	loaded, err := dataStore.GetSite(ctx, created.ID)
	if err != nil {
		t.Fatalf("get site: %v", err)
	}
	if loaded.Host != "example.test" {
		t.Fatalf("unexpected host %q", loaded.Host)
	}
}

func TestMemoryStorePolicyRejectsMissingBindings(t *testing.T) {
	ctx := context.Background()
	dataStore := NewMemoryStore()

	_, err := dataStore.CreatePolicy(ctx, model.Policy{
		Name:          "Invalid",
		RiskThreshold: 100,
		DefaultAction: "block",
		Enabled:       true,
		SiteIDs:       []int64{404},
		RuleIDs:       []int64{1},
	})
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStoreProtectionRuleValidationAndBackfill(t *testing.T) {
	ctx := context.Background()
	dataStore := NewMemoryStore()

	_, err := dataStore.CreateProtectionRule(ctx, model.ProtectionRule{
		Name:     "bad",
		Module:   "cc-protection",
		Category: "upload",
		Enabled:  true,
		Match: model.ProtectionRuleMatch{
			Path:      "/api",
			PathMatch: "prefix",
		},
		Limit: model.ProtectionRuleLimit{
			Counter:   "client_ip",
			Threshold: 10,
			WindowSec: 60,
		},
		Action: model.ProtectionRuleAction{Type: "block"},
	})
	if err == nil {
		t.Fatal("expected invalid module/category mapping to fail")
	}

	legacy, err := dataStore.CreateRateLimitRule(ctx, model.RateLimitRule{
		Name:       "Login limit",
		Scope:      "ip",
		PathMatch:  "exact",
		MatchValue: "/login",
		Threshold:  10,
		WindowSec:  60,
		Action:     "block",
		CCAction:   "ban",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("create legacy rate limit: %v", err)
	}
	created, err := dataStore.BackfillProtectionRules(ctx)
	if err != nil {
		t.Fatalf("backfill protection rules: %v", err)
	}
	if created < 1 {
		t.Fatalf("expected backfilled rules, got %d", created)
	}
	created, err = dataStore.BackfillProtectionRules(ctx)
	if err != nil {
		t.Fatalf("rerun backfill: %v", err)
	}
	if created != 0 {
		t.Fatalf("expected idempotent backfill, got %d new rows", created)
	}
	rules, err := dataStore.ListProtectionRules(ctx)
	if err != nil {
		t.Fatalf("list protection rules: %v", err)
	}
	var rule model.ProtectionRule
	for _, item := range rules {
		if item.LegacyRef == protectionrules.LegacyRef("rate_limits", legacy.ID) {
			rule = item
			break
		}
	}
	if rule.LegacyRef != protectionrules.LegacyRef("rate_limits", legacy.ID) || rule.MigrationStatus != protectionrules.StatusMigrated {
		t.Fatalf("unexpected migration metadata: %+v", rule)
	}
	if rule.Module != protectionrules.ModuleCC || rule.Limit.Counter != "client_ip" || rule.Action.Type != "ban" {
		t.Fatalf("unexpected backfilled rule: %+v", rule)
	}
}
