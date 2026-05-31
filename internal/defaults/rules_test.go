package defaults_test

import (
	"context"
	"testing"

	"litewaf-api/internal/defaults"
	"litewaf-api/internal/model"
	"litewaf-api/internal/store"
)

func TestSeedRulesIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()

	if err := defaults.SeedRules(ctx, dataStore); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if err := defaults.SeedRules(ctx, dataStore); err != nil {
		t.Fatalf("seed rules again: %v", err)
	}

	rules, err := dataStore.ListRules(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != len(defaults.DefaultRules) {
		t.Fatalf("expected %d rules, got %d", len(defaults.DefaultRules), len(rules))
	}

	seen := map[string]bool{}
	for _, rule := range rules {
		if seen[rule.Name] {
			t.Fatalf("duplicate default rule %q", rule.Name)
		}
		seen[rule.Name] = true
		if rule.Module != "attack-protection" || rule.Category != "managed" || rule.AttackType == "" || rule.Group == "" || rule.Priority <= 0 {
			t.Fatalf("expected managed attack metadata on default rule: %+v", rule)
		}
	}
}

func TestDefaultRulesIncludeBaselineFamilies(t *testing.T) {
	types := map[string]bool{}
	for _, rule := range defaults.DefaultRules {
		types[rule.Type] = true
	}
	for _, typ := range []string{"sqli", "xss", "rce", "path-traversal"} {
		if !types[typ] {
			t.Fatalf("expected default %s rule", typ)
		}
	}
}

func TestSeedRulesUpgradesLegacyNames(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	if _, err := dataStore.CreateRule(ctx, model.Rule{
		Name: "MVP SQLi baseline", Type: "sqli", Target: "args", Action: "block", Expression: "(?i)union", Score: 80, Enabled: true,
	}); err != nil {
		t.Fatalf("create legacy rule: %v", err)
	}

	if err := defaults.SeedRules(ctx, dataStore); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	rules, err := dataStore.ListRules(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	for _, rule := range rules {
		if rule.Name == "MVP SQLi baseline" {
			t.Fatal("expected legacy rule name to be upgraded")
		}
	}
}
