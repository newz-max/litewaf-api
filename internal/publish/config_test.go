package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
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

func TestGenerateExtendedGatewayConfigPrefersMigratedProtectionRules(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	legacy, err := dataStore.CreateRateLimitRule(ctx, model.RateLimitRule{
		Name: "Legacy login limit", Scope: "ip", MatchValue: "/login", PathMatch: "exact",
		Methods: []string{"POST"}, Threshold: 10, WindowSec: 60, Action: "block", CCAction: "ban",
		BanDuration: 300, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create legacy rate limit: %v", err)
	}
	_, err = dataStore.CreateProtectionRule(ctx, model.ProtectionRule{
		Name:            "Migrated login limit",
		Module:          "cc-protection",
		Category:        "rate-limit",
		Enabled:         true,
		Priority:        70,
		Source:          protectionrules.SourceLegacy,
		MigrationStatus: protectionrules.StatusMigrated,
		LegacyRef:       protectionrules.LegacyRef("rate_limits", legacy.ID),
		Match: model.ProtectionRuleMatch{
			Path: "/login", PathMatch: "exact", Methods: []string{"POST"},
		},
		Limit: model.ProtectionRuleLimit{
			Counter: "client_ip", Threshold: 10, WindowSec: 60, BanDurationSec: 300,
		},
		Action: model.ProtectionRuleAction{Type: "ban"},
	})
	if err != nil {
		t.Fatalf("create migrated protection rule: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-migrated")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if len(config.RateLimits) != 1 {
		t.Fatalf("expected legacy rate_limits compatibility output, got %+v", config.RateLimits)
	}
	if len(config.ProtectionRules) != 1 {
		t.Fatalf("expected deduplicated protection_rules output, got %+v", config.ProtectionRules)
	}
	if config.ProtectionRules[0].Name != "Migrated login limit" || config.ProtectionRules[0].LegacyRef == "" {
		t.Fatalf("expected migrated rule to be preferred, got %+v", config.ProtectionRules[0])
	}
}

func TestGenerateExtendedGatewayConfigIncludesAdvancedCCProtectionRules(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateProtectionRule(ctx, model.ProtectionRule{
		Name:     "Session glob limit",
		Module:   "cc-protection",
		Category: "rate-limit",
		SiteID:   3,
		Enabled:  true,
		Priority: 60,
		Match: model.ProtectionRuleMatch{
			Path: "/api/*/login", PathMatch: "glob", Methods: []string{"POST"},
		},
		Limit: model.ProtectionRuleLimit{
			Counter: "session", SessionSource: "cookie", SessionName: "sid",
			Threshold: 5, WindowSec: 60, BanDurationSec: 120,
		},
		Action: model.ProtectionRuleAction{Type: "block"},
	})
	if err != nil {
		t.Fatalf("create advanced cc protection rule: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-advanced-cc")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if len(config.ProtectionRules) != 1 {
		t.Fatalf("expected advanced cc protection rule output, got %+v", config.ProtectionRules)
	}
	rule := config.ProtectionRules[0]
	if rule.Match.PathMatch != "glob" || rule.Limit.Counter != "session" || rule.Limit.SessionName != "sid" || rule.Limit.SessionSource != "cookie" {
		t.Fatalf("advanced cc fields lost in publish output: %+v", rule)
	}
	if len(config.RateLimits) != 0 {
		t.Fatalf("native advanced cc rule should not fabricate legacy rate_limits output: %+v", config.RateLimits)
	}
}

func TestStoreRejectsInvalidAdvancedCCProtectionRuleBeforePublish(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateProtectionRule(ctx, model.ProtectionRule{
		Name:     "Invalid glob",
		Module:   "cc-protection",
		Category: "rate-limit",
		Enabled:  true,
		Match: model.ProtectionRuleMatch{
			Path: "/api/**", PathMatch: "glob",
		},
		Limit: model.ProtectionRuleLimit{
			Counter: "client_ip", Threshold: 1, WindowSec: 1,
		},
		Action: model.ProtectionRuleAction{Type: "block"},
	})
	if err == nil {
		t.Fatal("expected invalid advanced cc rule to be rejected before publish")
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

func TestGenerateExtendedGatewayConfigIncludesBotEnhancementFields(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateProtectionRule(ctx, model.ProtectionRule{
		Name:     "Captcha challenge",
		Module:   "bot-protection",
		Category: "challenge",
		SiteID:   3,
		Enabled:  true,
		Priority: 45,
		Match: model.ProtectionRuleMatch{
			Path:      "/checkout",
			PathMatch: "prefix",
			Methods:   []string{"GET", "POST"},
		},
		Challenge: &model.ProtectionRuleChallenge{
			Mode:               "captcha",
			VerifyTTL:          180,
			FailureAction:      "block",
			BehaviorEnabled:    true,
			BehaviorThreshold:  55,
			DeviceBinding:      true,
			SearchEngineBypass: true,
			FailureMessage:     "验证失败",
			PrivacyNotice:      "仅使用本地验证信号",
		},
		Action: model.ProtectionRuleAction{Type: "block"},
	})
	if err != nil {
		t.Fatalf("create bot enhancement rule: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-bot-enhancement")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if len(config.ProtectionRules) != 1 {
		t.Fatalf("expected bot enhancement output, got %+v", config.ProtectionRules)
	}
	challenge := config.ProtectionRules[0].Challenge
	if challenge == nil || challenge.Mode != "captcha" || challenge.VerifyTTL != 180 || challenge.FailureAction != "block" {
		t.Fatalf("unexpected bot enhancement challenge: %+v", challenge)
	}
	if !challenge.BehaviorEnabled || challenge.BehaviorThreshold != 55 || !challenge.DeviceBinding || !challenge.SearchEngineBypass {
		t.Fatalf("unexpected bot enhancement fields: %+v", challenge)
	}
	if challenge.FailureMessage != "验证失败" || challenge.PrivacyNotice != "仅使用本地验证信号" {
		t.Fatalf("unexpected bot enhancement display text: %+v", challenge)
	}
}

func TestGenerateExtendedGatewayConfigIncludesDynamicProtectionRules(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateDynamicProtectionRule(ctx, model.DynamicProtectionRule{
		Name: "Admin token", Category: "dynamic-token", Path: "/admin", PathMatch: "prefix", Methods: []string{"GET"},
		TokenTTL: 600, TokenPlacement: "cookie", FailureAction: "block", SiteID: 3, Enabled: true, Priority: 55,
	})
	if err != nil {
		t.Fatalf("create dynamic protection rule: %v", err)
	}
	_, err = dataStore.CreateDynamicProtectionRule(ctx, model.DynamicProtectionRule{
		Name: "Disabled", Category: "waiting-room", Path: "/", PathMatch: "prefix", QueueCapacity: 20, AdmissionTTL: 120, RetryInterval: 5, OverflowAction: "waiting-room", Enabled: false,
	})
	if err != nil {
		t.Fatalf("create disabled dynamic protection rule: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-dynamic-protection")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if len(config.ProtectionRules) != 1 {
		t.Fatalf("expected dynamic protection output, got %+v", config.ProtectionRules)
	}
	rule := config.ProtectionRules[0]
	if rule.Module != "dynamic-protection" || rule.Category != "dynamic-token" || rule.Action.Type != "block" {
		t.Fatalf("unexpected dynamic protection identity/action: %+v", rule)
	}
	if rule.Match.Path != "/admin" || rule.Match.PathMatch != "prefix" || len(rule.Match.Methods) != 1 || rule.Priority != 55 {
		t.Fatalf("unexpected dynamic protection match/priority: %+v", rule)
	}
	if rule.Dynamic == nil || rule.Dynamic.TokenTTL != 600 || rule.Dynamic.TokenPlacement != "cookie" || rule.Dynamic.FailureAction != "block" {
		t.Fatalf("unexpected dynamic protection config: %+v", rule.Dynamic)
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

func TestValidateRejectsInvalidDynamicProtectionRule(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateDynamicProtectionRule(ctx, model.DynamicProtectionRule{
		Name: "Bad token", Category: "dynamic-token", Path: "admin", PathMatch: "prefix", TokenTTL: 300, TokenPlacement: "cookie", FailureAction: "block", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create invalid dynamic rule: %v", err)
	}
	if _, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-invalid-dynamic-protection"); err == nil {
		t.Fatal("expected invalid dynamic protection rule to block publish")
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

func TestGenerateKeepsPackageOriginMetadataGatewayCompatible(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	site, err := dataStore.CreateSite(ctx, model.Site{Name: "app", Host: "example.com", Upstream: "http://127.0.0.1:9000", Mode: "protect", Enabled: true})
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	rule, err := dataStore.CreateRule(ctx, model.Rule{
		Name: "Community XSS", Type: "xss", Target: "args", Action: "block", Expression: "(?i)<script", Score: 80, Enabled: true,
		Module: "attack-protection", Category: "managed", AttackType: "xss", Group: "XSS 防护", Priority: 100,
		PackageID: "community-baseline", PackageVersion: "v1", PackageRuleID: "xss-query", SourceChecksum: "checksum",
		SignatureStatus: "unsigned", ReviewStatus: "approved", LastTestStatus: "passed",
		RemoteCatalogID: "1", LastSyncedVersion: "v1", PendingUpdateState: "current", LocalOverrideState: "none", ExportEligible: true,
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := dataStore.CreatePolicy(ctx, model.Policy{Name: "default", SiteIDs: []int64{site.ID}, RuleIDs: []int64{rule.ID}, Enabled: true}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	config, payload, _, err := GenerateExtended(ctx, dataStore, "ruleset-package")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(config.Sites) != 1 || len(config.Sites[0].Rules) != 1 {
		t.Fatalf("expected published package rule, got %+v", config.Sites)
	}
	published := config.Sites[0].Rules[0]
	if published.PackageID != "community-baseline" || published.PackageRuleID != "xss-query" {
		t.Fatalf("missing package metadata: %+v", published)
	}
	if bytes.Contains(payload, []byte("remote_catalog_id")) || bytes.Contains(payload, []byte("signature_status")) || bytes.Contains(payload, []byte("export_eligible")) {
		t.Fatalf("gateway payload leaked control-plane community metadata: %s", string(payload))
	}
}

func TestGenerateDoesNotLeakRuleCommunityPhaseTwoControlPlaneState(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	site, err := dataStore.CreateSite(ctx, model.Site{Name: "app", Host: "phase2.example.com", Upstream: "http://127.0.0.1:9000", Mode: "protect", Enabled: true})
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	rule, err := dataStore.CreateRule(ctx, model.Rule{
		Name: "Community SQLi", Type: "sqli", Target: "args", Action: "block", Expression: "(?i)union\\s+select", Score: 80, Enabled: true,
		Module: "attack-protection", Category: "managed", AttackType: "sqli", Group: "SQL 注入防护", Priority: 100,
		PackageID: "paid-pack", PackageVersion: "v1", PackageRuleID: "sqli-query", SourceChecksum: "checksum", ReviewStatus: "approved",
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := dataStore.CreatePolicy(ctx, model.Policy{Name: "default", SiteIDs: []int64{site.ID}, RuleIDs: []int64{rule.ID}, Enabled: true}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	account, err := dataStore.CreateRuleCommunityAccountSource(ctx, model.RuleCommunityAccountSource{
		Name: "Paid source", ProviderType: "https-catalog", Endpoint: "https://rules.example.com/catalog.json", Enabled: true, TimeoutSec: 5, SubscriptionStatus: "authorized", Status: "authorized",
	}, model.RuleCommunityAccountSecret{Secret: "secret-token"})
	if err != nil {
		t.Fatalf("create account source: %v", err)
	}
	if _, err := dataStore.CreateRuleReviewQueueItem(ctx, model.RuleReviewQueueItem{ItemType: "package-update", PackageID: "paid-pack", PackageVersion: "v2", SourceIdentity: "account:" + strconv.FormatInt(account.ID, 10), State: "queued"}); err != nil {
		t.Fatalf("create queue item: %v", err)
	}
	if _, err := dataStore.CreateRuleFeedback(ctx, model.RuleFeedback{RuleID: rule.ID, Reason: "false positive", Severity: "medium", Status: "open", RedactedSample: map[string]string{"path": "/search"}}); err != nil {
		t.Fatalf("create feedback: %v", err)
	}
	target, err := dataStore.CreateRuleContributionTarget(ctx, model.RuleContributionTarget{Name: "Push", Provider: "https", Endpoint: "https://community.example.com/push", Enabled: true}, model.RuleCommunityAccountSecret{Secret: "push-secret"})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	if _, err := dataStore.CreateRuleContributionPushAttempt(ctx, model.RuleContributionPushAttempt{TargetID: target.ID, TargetName: target.Name, PackageID: "paid-pack", PackageVersion: "v1", Checksum: "abc", Status: "delivered", Actor: "admin"}); err != nil {
		t.Fatalf("create push attempt: %v", err)
	}

	_, payload, _, err := GenerateExtended(ctx, dataStore, "ruleset-phase2")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte("rule_community_account"),
		[]byte("subscription_status"),
		[]byte("credential"),
		[]byte("secret-token"),
		[]byte("review_queue"),
		[]byte("feedback"),
		[]byte("contribution"),
	} {
		if bytes.Contains(payload, forbidden) {
			t.Fatalf("gateway payload leaked %s: %s", string(forbidden), string(payload))
		}
	}
}

func TestGenerateDoesNotLeakRuleProviderControlPlaneState(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	site, err := dataStore.CreateSite(ctx, model.Site{Name: "app", Host: "provider.example.com", Upstream: "http://127.0.0.1:9000", Mode: "protect", Enabled: true})
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	provider, err := dataStore.CreateRuleProviderAdapter(ctx, model.RuleProviderAdapter{
		Name: "Provider feed", ProviderType: "https-catalog", Endpoint: "https://rules.example.com/catalog.json", AuthMode: "bearer-token", Enabled: true, TimeoutSec: 5,
		RetryPolicy:  model.RuleProviderRetryPolicy{MaxAttempts: 2, BackoffSec: 60},
		Credential:   model.RuleAccountCredential{Alias: "prod"},
		HealthStatus: "healthy", SyncStatus: "synced",
	}, model.RuleCommunityAccountSecret{Secret: "provider-secret"})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	rule, err := dataStore.CreateRule(ctx, model.Rule{
		Name: "Provider SQLi", Type: "sqli", Target: "args", Action: "block", Expression: "(?i)union\\s+select", Score: 80, Enabled: true,
		Module: "attack-protection", Category: "managed", AttackType: "sqli", Group: "SQL 注入防护", Priority: 100,
		PackageID: "provider-pack", PackageVersion: "v1", PackageRuleID: "provider-sqli", SourceChecksum: "checksum", ReviewStatus: "approved",
		ProviderID: provider.ID, ProviderName: provider.Name, ProviderPackageRef: "provider-pack@v1",
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := dataStore.UpdateRuleProviderSyncState(ctx, provider.ID, model.RuleProviderAdapter{
		ID: provider.ID, Name: provider.Name, ProviderType: provider.ProviderType, Endpoint: provider.Endpoint, AuthMode: provider.AuthMode, Enabled: true, TimeoutSec: 5,
		RetryPolicy: provider.RetryPolicy, Credential: provider.Credential, HealthStatus: "unauthorized", SyncStatus: "failed", LastError: "provider authorization denied",
		AttemptCount: 2, RetryExhausted: true,
	}, []model.RuleProviderPackage{{
		ProviderID: provider.ID, ProviderName: provider.Name, ProviderType: provider.ProviderType, ProviderPackageRef: "provider-pack@v1",
		PackageID: "provider-pack", Name: "Provider Pack", Version: "v1", Compatibility: "litewaf-rule-package-v1", Checksum: "checksum",
		EntitlementState: "denied", SyncStatus: "failed", Stale: true,
	}}); err != nil {
		t.Fatalf("update provider state: %v", err)
	}
	if _, err := dataStore.CreatePolicy(ctx, model.Policy{Name: "default", SiteIDs: []int64{site.ID}, RuleIDs: []int64{rule.ID}, Enabled: true}); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	config, payload, _, err := GenerateExtended(ctx, dataStore, "ruleset-provider")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(config.Sites) != 1 || len(config.Sites[0].Rules) != 1 {
		t.Fatalf("expected provider-origin rule in gateway config, got %+v", config.Sites)
	}
	published := config.Sites[0].Rules[0]
	if published.PackageID != "provider-pack" || published.PackageRuleID != "provider-sqli" {
		t.Fatalf("expected package identity only, got %+v", published)
	}
	for _, forbidden := range [][]byte{
		[]byte("provider_id"),
		[]byte("provider_name"),
		[]byte("provider_package_ref"),
		[]byte("rule_provider"),
		[]byte("credential"),
		[]byte("provider-secret"),
		[]byte("entitlement"),
		[]byte("retry"),
		[]byte("authorization denied"),
		[]byte("stale"),
	} {
		if bytes.Contains(payload, forbidden) {
			t.Fatalf("gateway payload leaked %s: %s", string(forbidden), string(payload))
		}
	}
}
