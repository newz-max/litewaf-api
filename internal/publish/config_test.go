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
		Name: "CC", Scope: "ip", MatchValue: "/login", PathMatch: "exact", Methods: []string{"POST"}, Threshold: 10, WindowSec: 60, Action: "block", CCAction: "ban", BanDuration: 300, ViolationThreshold: 3, ViolationWindowSec: 120, Enabled: true,
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
	if config.Sites[0].Rules[0].Module != "attack-protection" || config.Sites[0].Rules[0].AttackType != "xss" {
		t.Fatalf("expected attack protection metadata, got %+v", config.Sites[0].Rules[0])
	}
	if config.RateLimits[0].ViolationThreshold != 3 {
		t.Fatalf("expected repeated violation settings, got %+v", config.RateLimits[0])
	}
	if len(config.ProtectionRules) != 1 {
		t.Fatalf("expected protection_rules output, got %+v", config.ProtectionRules)
	}
	ccRule := config.ProtectionRules[0]
	if ccRule.Module != "cc-protection" || ccRule.Category != "rate-limit" {
		t.Fatalf("unexpected protection rule identity: %+v", ccRule)
	}
	if ccRule.Match.Path != "/login" || ccRule.Match.PathMatch != "exact" || len(ccRule.Match.Methods) != 1 || ccRule.Match.Methods[0] != "POST" {
		t.Fatalf("unexpected protection rule match: %+v", ccRule.Match)
	}
	if ccRule.Limit.Counter != "client_ip" || ccRule.Action.Type != "ban" {
		t.Fatalf("unexpected protection rule limit/action: %+v", ccRule)
	}
}

func TestGenerateExtendedGatewayConfigIncludesAttackProtectionMetadata(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	site, err := dataStore.CreateSite(ctx, model.Site{
		Name: "Attack", Host: "attack.local", Upstream: "http://upstream", Mode: "protect", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	rules, err := dataStore.ListRules(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	var ids []int64
	foundTraversal := false
	for _, rule := range rules {
		if rule.Module == "attack-protection" && rule.Category == "managed" {
			ids = append(ids, rule.ID)
		}
		if rule.AttackType == "path-traversal" && rule.Target == "normalized_path" {
			foundTraversal = true
		}
	}
	if len(ids) != 4 || !foundTraversal {
		t.Fatalf("expected four managed attack rules and traversal metadata, ids=%v foundTraversal=%v", ids, foundTraversal)
	}
	_, err = dataStore.CreatePolicy(ctx, model.Policy{
		Name: "Attack", RiskThreshold: 100, DefaultAction: "block", Enabled: true, SiteIDs: []int64{site.ID}, RuleIDs: ids,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-attack")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if len(config.Sites) != 1 || len(config.Sites[0].Rules) != 4 {
		t.Fatalf("unexpected attack protection rules: %+v", config.Sites)
	}
	for _, rule := range config.Sites[0].Rules {
		if rule.Module != "attack-protection" || rule.Category != "managed" || rule.AttackType == "" || rule.Group == "" || rule.Priority <= 0 {
			t.Fatalf("missing attack protection metadata: %+v", rule)
		}
	}
}

func TestGenerateExtendedGatewayConfigIncludesAccessControlProtectionRules(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateAccessListEntry(ctx, model.AccessListEntry{
		Name: "Admin path block", Kind: "blacklist", Target: "uri", Value: "/admin", MatchOperator: "prefix", Action: "block", SiteID: 3, Enabled: true, Priority: 80,
	})
	if err != nil {
		t.Fatalf("create access control entry: %v", err)
	}
	_, err = dataStore.CreateAccessListEntry(ctx, model.AccessListEntry{
		Name: "Disabled", Kind: "blacklist", Target: "ip", Value: "203.0.113.1", Action: "block", Enabled: false,
	})
	if err != nil {
		t.Fatalf("create disabled entry: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-access-control")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if len(config.AccessLists) != 1 {
		t.Fatalf("expected legacy access list compatibility output, got %+v", config.AccessLists)
	}
	if len(config.ProtectionRules) != 1 {
		t.Fatalf("expected access control protection rule output, got %+v", config.ProtectionRules)
	}
	rule := config.ProtectionRules[0]
	if rule.Module != "access-control" || rule.Category != "access-control" || rule.Action.Type != "block" {
		t.Fatalf("unexpected access control identity/action: %+v", rule)
	}
	if rule.Match.Target != "path" || rule.Match.Path != "/admin" || rule.Match.PathMatch != "prefix" || rule.Priority != 80 {
		t.Fatalf("unexpected access control match/priority: %+v", rule)
	}
}

func TestGenerateExtendedGatewayConfigIncludesUploadProtectionRules(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateUploadProtectionRule(ctx, model.UploadProtectionRule{
		Name: "Script upload block", Path: "/upload", PathMatch: "prefix", Methods: []string{"POST"},
		Extensions: []string{"php", "jsp"}, MaxBytes: 2097152, Action: "block", SiteID: 3, Enabled: true, Priority: 90,
	})
	if err != nil {
		t.Fatalf("create upload protection rule: %v", err)
	}
	_, err = dataStore.CreateUploadProtectionRule(ctx, model.UploadProtectionRule{
		Name: "Disabled", Path: "/upload", PathMatch: "prefix", Extensions: []string{"exe"}, Action: "block", Enabled: false,
	})
	if err != nil {
		t.Fatalf("create disabled upload protection rule: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-upload-protection")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if len(config.ProtectionRules) != 1 {
		t.Fatalf("expected upload protection output, got %+v", config.ProtectionRules)
	}
	rule := config.ProtectionRules[0]
	if rule.Module != "upload-protection" || rule.Category != "upload" || rule.Action.Type != "block" {
		t.Fatalf("unexpected upload protection identity/action: %+v", rule)
	}
	if rule.Match.Path != "/upload" || rule.Match.PathMatch != "prefix" || len(rule.Match.Methods) != 1 || rule.Priority != 90 {
		t.Fatalf("unexpected upload protection match/priority: %+v", rule)
	}
	if rule.Upload == nil || len(rule.Upload.Extensions) != 2 || rule.Upload.MaxBytes != 2097152 {
		t.Fatalf("unexpected upload protection constraints: %+v", rule.Upload)
	}
}

func TestGenerateExtendedGatewayConfigIncludesBotProtectionRules(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateBotProtectionRule(ctx, model.BotProtectionRule{
		Name: "Admin challenge", Path: "/admin", PathMatch: "prefix", Methods: []string{"GET"},
		ChallengeMode: "js-challenge", VerifyTTL: 600, FailureAction: "block", SiteID: 3, Enabled: true, Priority: 60,
	})
	if err != nil {
		t.Fatalf("create bot protection rule: %v", err)
	}
	_, err = dataStore.CreateBotProtectionRule(ctx, model.BotProtectionRule{
		Name: "Disabled", Path: "/login", PathMatch: "exact", ChallengeMode: "js-challenge", VerifyTTL: 300, FailureAction: "block", Enabled: false,
	})
	if err != nil {
		t.Fatalf("create disabled bot protection rule: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-bot-protection")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if len(config.ProtectionRules) != 1 {
		t.Fatalf("expected bot protection output, got %+v", config.ProtectionRules)
	}
	rule := config.ProtectionRules[0]
	if rule.Module != "bot-protection" || rule.Category != "challenge" || rule.Action.Type != "block" {
		t.Fatalf("unexpected bot protection identity/action: %+v", rule)
	}
	if rule.Match.Path != "/admin" || rule.Match.PathMatch != "prefix" || len(rule.Match.Methods) != 1 || rule.Priority != 60 {
		t.Fatalf("unexpected bot protection match/priority: %+v", rule)
	}
	if rule.Challenge == nil || rule.Challenge.Mode != "js-challenge" || rule.Challenge.VerifyTTL != 600 || rule.Challenge.FailureAction != "block" {
		t.Fatalf("unexpected bot protection challenge: %+v", rule.Challenge)
	}
}

func TestValidateRejectsInvalidAccessControlRule(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateAccessListEntry(ctx, model.AccessListEntry{
		Name: "Bad path", Kind: "blacklist", Target: "uri", Value: "admin", MatchOperator: "prefix", Action: "block", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create invalid entry: %v", err)
	}
	if _, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-invalid-access-control"); err == nil {
		t.Fatal("expected invalid access control rule to block publish")
	}
}

func TestValidateRejectsInvalidUploadProtectionRule(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateUploadProtectionRule(ctx, model.UploadProtectionRule{
		Name: "Bad path", Path: "upload", PathMatch: "prefix", Extensions: []string{"php"}, Action: "block", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create invalid upload rule: %v", err)
	}
	if _, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-invalid-upload-protection"); err == nil {
		t.Fatal("expected invalid upload protection rule to block publish")
	}
}

func TestValidateRejectsInvalidBotProtectionRule(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateBotProtectionRule(ctx, model.BotProtectionRule{
		Name: "Bad path", Path: "admin", PathMatch: "prefix", ChallengeMode: "js-challenge", VerifyTTL: 300, FailureAction: "block", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create invalid bot rule: %v", err)
	}
	if _, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-invalid-bot-protection"); err == nil {
		t.Fatal("expected invalid bot protection rule to block publish")
	}
}

func TestValidateRejectsInvalidAttackProtectionMetadata(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		rule model.Rule
	}{
		{
			name: "unsupported attack type",
			rule: model.Rule{
				Name: "Bad attack type", Type: "custom", Target: "args", Action: "block", Expression: "(?i)bad", Score: 10, Enabled: true,
				Module: "attack-protection", Category: "managed", AttackType: "unknown", Group: "Bad", Priority: 100,
			},
		},
		{
			name: "unsupported action",
			rule: model.Rule{
				Name: "Bad action", Type: "sqli", Target: "args", Action: "pass", Expression: "(?i)select", Score: 10, Enabled: true,
				Module: "attack-protection", Category: "managed", AttackType: "sqli", Group: "SQL 注入防护", Priority: 100,
			},
		},
		{
			name: "missing priority",
			rule: model.Rule{
				Name: "Bad priority", Type: "sqli", Target: "args", Action: "block", Expression: "(?i)select", Score: 10, Enabled: true,
				Module: "attack-protection", Category: "managed", AttackType: "sqli", Group: "SQL 注入防护", Priority: -1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataStore := store.NewMemoryStore()
			site, err := dataStore.CreateSite(ctx, model.Site{
				Name: "Attack", Host: "attack.local", Upstream: "http://upstream", Mode: "protect", Enabled: true,
			})
			if err != nil {
				t.Fatalf("create site: %v", err)
			}
			rule, err := dataStore.CreateRule(ctx, tt.rule)
			if err != nil {
				t.Fatalf("create rule: %v", err)
			}
			_, err = dataStore.CreatePolicy(ctx, model.Policy{
				Name: "Attack", RiskThreshold: 100, DefaultAction: "block", Enabled: true, SiteIDs: []int64{site.ID}, RuleIDs: []int64{rule.ID},
			})
			if err != nil {
				t.Fatalf("create policy: %v", err)
			}
			if _, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-invalid"); err == nil {
				t.Fatal("expected invalid attack protection metadata to block publish")
			}
		})
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
