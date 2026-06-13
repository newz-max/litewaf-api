package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

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
	if len(config.Applications) != 1 {
		t.Fatalf("expected 1 application, got %d", len(config.Applications))
	}
	if len(config.Applications[0].Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(config.Applications[0].Rules))
	}
	if config.Applications[0].Policy.RiskThreshold != 100 {
		t.Fatalf("expected published policy threshold, got %+v", config.Applications[0].Policy)
	}
	var decoded GatewayConfig
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if len(decoded.Applications) != 1 {
		t.Fatalf("expected payload applications, got %+v", decoded.Applications)
	}
	if bytes.Contains(payload, []byte(`"sites"`)) {
		t.Fatalf("payload must not include legacy sites field: %s", payload)
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
	if !config.Applications[0].Policy.BodyInspectionEnabled || !config.Applications[0].Policy.DynamicBanEnabled {
		t.Fatalf("expected advanced policy settings: %+v", config.Applications[0].Policy)
	}
	if config.Applications[0].Rules[0].Target != "body_json" {
		t.Fatalf("expected advanced rule target, got %+v", config.Applications[0].Rules[0])
	}
	if config.Applications[0].Rules[0].Module != "attack-protection" || config.Applications[0].Rules[0].AttackType != "xss" {
		t.Fatalf("expected attack protection metadata, got %+v", config.Applications[0].Rules[0])
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
	if len(config.Applications) != 1 || len(config.Applications[0].Rules) != 4 {
		t.Fatalf("unexpected attack protection rules: %+v", config.Applications)
	}
	for _, rule := range config.Applications[0].Rules {
		if rule.Module != "attack-protection" || rule.Category != "managed" || rule.AttackType == "" || rule.Group == "" || rule.Priority <= 0 {
			t.Fatalf("missing attack protection metadata: %+v", rule)
		}
	}
}

func TestGenerateExtendedGatewayConfigIncludesOptimizedIPAccessIndex(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	exact, err := dataStore.CreateIPAccessListEntry(ctx, model.IPAccessListEntry{
		Name: "Office allow", Kind: "allow", Target: "ip", Value: "203.0.113.10", SiteID: 3, Enabled: true, Priority: 80,
	})
	if err != nil {
		t.Fatalf("create exact entry: %v", err)
	}
	cidr, err := dataStore.CreateIPAccessListEntry(ctx, model.IPAccessListEntry{
		Name: "Blocked range", Kind: "block", Target: "cidr", Value: "198.51.100.0/24", SiteID: 0, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create cidr entry: %v", err)
	}
	_, err = dataStore.CreateIPAccessListEntry(ctx, model.IPAccessListEntry{
		Name: "Disabled", Kind: "block", Target: "ip", Value: "203.0.113.1", Enabled: false,
	})
	if err != nil {
		t.Fatalf("create disabled entry: %v", err)
	}
	config, payload, _, err := GenerateExtended(ctx, dataStore, "ruleset-ip-access")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	exactID := strconv.FormatInt(exact.ID, 10)
	if config.IPAccessIndex.Exact.Allow["site:3"]["203.0.113.10"] != exactID {
		t.Fatalf("expected exact allow index to map to entry id, got %+v", config.IPAccessIndex.Exact.Allow)
	}
	cidrID := strconv.FormatInt(cidr.ID, 10)
	if config.IPAccessIndex.CIDR.Block["global"]["ipv4"]["24"]["198.51.100.0"] != cidrID {
		t.Fatalf("expected cidr block index to map to entry id, got %+v", config.IPAccessIndex.CIDR.Block)
	}
	if len(config.IPAccessIndex.Entries) != 2 {
		t.Fatalf("disabled entries must be omitted from runtime index, got %+v", config.IPAccessIndex.Entries)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, ok := raw["access_lists"]; ok {
		t.Fatalf("legacy access_lists field must be absent: %s", payload)
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
		Name: "Script upload block", Path: "/api/*/upload", PathMatch: "glob", Methods: []string{"POST"},
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
	if rule.Match.Path != "/api/*/upload" || rule.Match.PathMatch != "glob" || len(rule.Match.Methods) != 1 || rule.Priority != 90 {
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
		Name: "Admin challenge", Path: "/admin/*", PathMatch: "glob", Methods: []string{"GET"},
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
	if rule.Match.Path != "/admin/*" || rule.Match.PathMatch != "glob" || len(rule.Match.Methods) != 1 || rule.Priority != 60 {
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
		Name: "Admin token", Category: "dynamic-token", Path: "/admin/*", PathMatch: "glob", Methods: []string{"GET"},
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
	if rule.Match.Path != "/admin/*" || rule.Match.PathMatch != "glob" || len(rule.Match.Methods) != 1 || rule.Priority != 55 {
		t.Fatalf("unexpected dynamic protection match/priority: %+v", rule)
	}
	if rule.Dynamic == nil || rule.Dynamic.TokenTTL != 600 || rule.Dynamic.TokenPlacement != "cookie" || rule.Dynamic.FailureAction != "block" {
		t.Fatalf("unexpected dynamic protection config: %+v", rule.Dynamic)
	}
}

func TestGenerateExtendedGatewayConfigIncludesAccessControlGlobRule(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateProtectionRule(ctx, model.ProtectionRule{
		Name:     "Admin glob block",
		Module:   "access-control",
		Category: "access-control",
		Enabled:  true,
		Priority: 50,
		Match: model.ProtectionRuleMatch{
			Target:    "path",
			Path:      "/admin/*",
			PathMatch: "glob",
		},
		Action: model.ProtectionRuleAction{Type: "block"},
	})
	if err != nil {
		t.Fatalf("create access control glob rule: %v", err)
	}
	config, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-access-glob")
	if err != nil {
		t.Fatalf("generate extended: %v", err)
	}
	if len(config.ProtectionRules) != 1 {
		t.Fatalf("expected access control output, got %+v", config.ProtectionRules)
	}
	rule := config.ProtectionRules[0]
	if rule.Module != "access-control" || rule.Match.Target != "path" || rule.Match.Path != "/admin/*" || rule.Match.PathMatch != "glob" {
		t.Fatalf("unexpected access control glob rule: %+v", rule)
	}
}

func TestValidateRejectsInvalidIPAccessList(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	_, err := dataStore.CreateIPAccessListEntry(ctx, model.IPAccessListEntry{
		Name: "Bad CIDR", Kind: "block", Target: "cidr", Value: "198.51.100.0/99", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create invalid entry: %v", err)
	}
	if _, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-invalid-ip-access-list"); err == nil {
		t.Fatal("expected invalid ip access-list entry to block publish")
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

func TestValidateApplicationReadinessReportsCertificateDomainMismatch(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	cert, err := dataStore.CreateCertificate(ctx, model.Certificate{
		Name:        "Other cert",
		Domains:     []string{"other.example.test"},
		CertPEM:     "cert",
		KeyPEM:      "key",
		NotBefore:   time.Now().UTC().Add(-time.Hour),
		NotAfter:    time.Now().UTC().Add(time.Hour),
		Fingerprint: "abc123",
	})
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	_, err = dataStore.CreateApplication(ctx, model.Application{
		Name:    "App",
		Mode:    model.ApplicationModeProtect,
		Enabled: true,
		Hosts: []model.ApplicationHost{
			{Host: "app.example.test", IsPrimary: true},
		},
		Listeners: []model.ApplicationListener{
			{Port: 443, Protocol: model.ListenerProtocolHTTPS, CertificateID: cert.ID, Enabled: true},
		},
		Upstreams: []model.ApplicationUpstream{
			{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}

	issues, err := ValidateApplicationReadiness(ctx, dataStore)
	if err != nil {
		t.Fatalf("validate readiness: %v", err)
	}
	if len(issues) != 1 || issues[0].Severity != "warning" || issues[0].Category != "certificate-domain-mismatch" {
		t.Fatalf("unexpected readiness issues: %+v", issues)
	}
	if _, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-warning"); err != nil {
		t.Fatalf("domain warning must not block publish generation: %v", err)
	}
}

func TestValidateApplicationReadinessBlocksListenerAndReferenceRisks(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	disabledApp, err := dataStore.CreateApplication(ctx, model.Application{
		Name:    "Disabled App",
		Mode:    model.ApplicationModeProtect,
		Enabled: false,
		Hosts: []model.ApplicationHost{
			{Host: "disabled.example.test", IsPrimary: true},
		},
		Listeners: []model.ApplicationListener{
			{Port: 80, Protocol: model.ListenerProtocolHTTP, Enabled: true},
		},
		Upstreams: []model.ApplicationUpstream{
			{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("create disabled app: %v", err)
	}
	rule, err := dataStore.CreateRule(ctx, model.Rule{Name: "SQLi", Type: "sqli", Target: "args", Action: "block", Expression: "select", Score: 100, Enabled: true})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := dataStore.CreatePolicy(ctx, model.Policy{Name: "disabled binding", SiteIDs: []int64{disabledApp.ID}, RuleIDs: []int64{rule.ID}, Enabled: true}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if _, err := dataStore.CreateProtectionRule(ctx, model.ProtectionRule{
		Name: "Disabled app CC", Module: "cc-protection", Category: "rate-limit", SiteID: disabledApp.ID, Enabled: true, Priority: 100,
		Match:  model.ProtectionRuleMatch{Path: "/", PathMatch: "prefix"},
		Limit:  model.ProtectionRuleLimit{Counter: "client_ip", Threshold: 10, WindowSec: 60},
		Action: model.ProtectionRuleAction{Type: "block"},
	}); err != nil {
		t.Fatalf("create protection rule: %v", err)
	}

	_, err = dataStore.CreateApplication(ctx, model.Application{
		Name:    "No Active Listener",
		Mode:    model.ApplicationModeProtect,
		Enabled: true,
		Hosts: []model.ApplicationHost{
			{Host: "nolisten.example.test", IsPrimary: true},
		},
		Listeners: []model.ApplicationListener{
			{Port: 8080, Protocol: model.ListenerProtocolHTTP, Enabled: false},
		},
		Upstreams: []model.ApplicationUpstream{
			{Name: "primary", URL: "http://127.0.0.1:9001", Weight: 1, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("create no-listener app: %v", err)
	}

	issues, err := ValidateApplicationReadiness(ctx, dataStore)
	if err != nil {
		t.Fatalf("validate readiness: %v", err)
	}
	categories := readinessCategories(issues)
	for _, category := range []string{"disabled-application-reference", "no-enabled-listener"} {
		if categories[category] == 0 {
			t.Fatalf("expected readiness category %s in %+v", category, issues)
		}
	}
	if _, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-invalid-readiness"); err == nil {
		t.Fatal("expected blocking readiness issues to stop publish generation")
	}
}

func TestValidateApplicationReadinessReportsListenerConflict(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	for _, name := range []string{"App One", "App Two"} {
		if _, err := dataStore.CreateApplication(ctx, model.Application{
			Name:    name,
			Mode:    model.ApplicationModeProtect,
			Enabled: true,
			Hosts: []model.ApplicationHost{
				{Host: "shared.example.test", IsPrimary: true},
			},
			Listeners: []model.ApplicationListener{
				{Port: 9443, Protocol: model.ListenerProtocolHTTP, Enabled: true},
			},
			Upstreams: []model.ApplicationUpstream{
				{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true},
			},
		}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	issues, err := ValidateApplicationReadiness(ctx, dataStore)
	if err != nil {
		t.Fatalf("validate readiness: %v", err)
	}
	categories := readinessCategories(issues)
	if categories["listener-port-conflict"] == 0 {
		t.Fatalf("expected listener conflict issue: %+v", issues)
	}
	if _, _, _, err := GenerateExtended(ctx, dataStore, "ruleset-listener-conflict"); err == nil {
		t.Fatal("expected listener conflict to block publish generation")
	}
}

func TestValidateApplicationReadinessBlocksBridgeRangePort(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	if _, err := dataStore.CreateApplication(ctx, model.Application{
		Name:    "Bridge App",
		Mode:    model.ApplicationModeProtect,
		Enabled: true,
		Hosts: []model.ApplicationHost{
			{Host: "bridge.example.test", IsPrimary: true},
		},
		Listeners: []model.ApplicationListener{
			{Port: 9443, Protocol: model.ListenerProtocolHTTP, Enabled: true},
		},
		Upstreams: []model.ApplicationUpstream{
			{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true},
		},
	}); err != nil {
		t.Fatalf("create bridge app: %v", err)
	}
	issues, err := ValidateApplicationReadinessWithDeployment(ctx, dataStore, GatewayListenerDeployment{
		Mode:            "bridge-range",
		BridgePortRange: "80,443,9000-9099",
	})
	if err != nil {
		t.Fatalf("validate readiness: %v", err)
	}
	categories := readinessCategories(issues)
	if categories["deployment-mode-port"] == 0 {
		t.Fatalf("expected deployment mode issue: %+v", issues)
	}
	if issues[0].Severity != "error" {
		t.Fatalf("expected bridge range issue to block activation: %+v", issues[0])
	}
}

func readinessCategories(issues []ApplicationValidationIssue) map[string]int {
	out := map[string]int{}
	for _, issue := range issues {
		out[issue.Category]++
	}
	return out
}

func TestWriteRuntimeArtifactsWritesListenersAndCertificates(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	cert, err := dataStore.CreateCertificate(ctx, model.Certificate{
		Name:        "App cert",
		Domains:     []string{"app.example.test"},
		CertPEM:     "CERTIFICATE-PEM",
		KeyPEM:      "PRIVATE-KEY-PEM",
		NotBefore:   time.Now().UTC().Add(-time.Hour),
		NotAfter:    time.Now().UTC().Add(time.Hour),
		Fingerprint: "def456",
	})
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	_, err = dataStore.CreateApplication(ctx, model.Application{
		Name:    "App",
		Mode:    model.ApplicationModeProtect,
		Enabled: true,
		Hosts: []model.ApplicationHost{
			{Host: "app.example.test", IsPrimary: true},
		},
		Listeners: []model.ApplicationListener{
			{Port: 80, Protocol: model.ListenerProtocolHTTP, Enabled: true},
			{Port: 443, Protocol: model.ListenerProtocolHTTPS, CertificateID: cert.ID, Enabled: true},
		},
		Upstreams: []model.ApplicationUpstream{
			{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}

	base := t.TempDir()
	artifacts, err := WriteRuntimeArtifacts(ctx, dataStore, filepath.Join(base, "active.json"))
	if err != nil {
		t.Fatalf("write artifacts: %v", err)
	}
	if artifacts.ListenerCount != 2 || artifacts.HTTPSListenerCount != 1 || len(artifacts.CertificateIDs) != 1 {
		t.Fatalf("unexpected artifact summary: %+v", artifacts)
	}
	listenerConf, err := os.ReadFile(filepath.Join(base, "listeners", "applications.conf"))
	if err != nil {
		t.Fatalf("read listener conf: %v", err)
	}
	if !bytes.Contains(listenerConf, []byte("listen 80;")) ||
		!bytes.Contains(listenerConf, []byte("listen 443 ssl;")) ||
		!bytes.Contains(listenerConf, []byte("ssl_certificate /etc/litewaf/certificates/1.crt;")) {
		t.Fatalf("listener config missing expected listeners: %s", listenerConf)
	}
	keyPEM, err := os.ReadFile(filepath.Join(base, "certificates", "1.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(keyPEM) != "PRIVATE-KEY-PEM\n" {
		t.Fatalf("unexpected key material written: %q", keyPEM)
	}
}

func TestWriteRuntimeArtifactsRendersProxyConfigAndSnippets(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	preserveHost := false
	if _, err := dataStore.CreateApplication(ctx, model.Application{
		Name:    "Proxy App",
		Mode:    model.ApplicationModeProtect,
		Enabled: true,
		Hosts: []model.ApplicationHost{
			{Host: "proxy.example.test", IsPrimary: true},
		},
		Listeners: []model.ApplicationListener{
			{Port: 80, Protocol: model.ListenerProtocolHTTP, Enabled: true},
		},
		Upstreams: []model.ApplicationUpstream{
			{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true},
		},
		ProxyConfig: &model.ApplicationProxyConfig{
			Headers:          []model.ApplicationProxyHeader{{Name: "X-App-Trace", Value: "$litewaf_request_id"}},
			ConnectTimeout:   "500ms",
			ReadTimeout:      "30s",
			WebSocketEnabled: true,
			PreserveHost:     &preserveHost,
			ProxyBuffering:   "off",
		},
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	if _, err := dataStore.SaveNginxConfigDraft(ctx, model.NginxConfigDraft{
		Mode: model.NginxConfigModeSnippets,
		Snippets: []model.NginxConfigSnippet{
			{IncludePoint: model.NginxSnippetPointHTTP, Content: "map $http_upgrade $litewaf_connection_upgrade { default upgrade; '' close; }"},
			{IncludePoint: model.NginxSnippetPointServer, Content: "client_header_timeout 30s;"},
			{IncludePoint: model.NginxSnippetPointLocation, Content: "proxy_hide_header X-Origin-Debug;"},
		},
		Validation: model.NginxValidationResult{Status: model.NginxValidationStatusUnchecked},
	}); err != nil {
		t.Fatalf("save nginx draft: %v", err)
	}

	base := t.TempDir()
	artifacts, err := WriteRuntimeArtifactsWithAdvancedNginx(ctx, dataStore, filepath.Join(base, "active.json"), "50m", writeExitScript(t, "nginx-ok", 0))
	if err != nil {
		t.Fatalf("write artifacts: %v", err)
	}
	if !artifacts.AdvancedConfig || artifacts.Validation.Status != model.NginxValidationStatusPassed {
		t.Fatalf("expected validated advanced artifacts: %+v", artifacts)
	}
	listenerConf, err := os.ReadFile(filepath.Join(base, "listeners", "applications.conf"))
	if err != nil {
		t.Fatalf("read listener conf: %v", err)
	}
	for _, want := range []string{
		"proxy_set_header Host $proxy_host;",
		"proxy_set_header Upgrade $http_upgrade;",
		"proxy_connect_timeout 500ms;",
		"proxy_read_timeout 30s;",
		"proxy_buffering off;",
		"proxy_set_header X-App-Trace $litewaf_request_id;",
		"client_header_timeout 30s;",
		"proxy_hide_header X-Origin-Debug;",
		"map $http_upgrade $litewaf_connection_upgrade",
	} {
		if !bytes.Contains(listenerConf, []byte(want)) {
			t.Fatalf("listener config missing %q:\n%s", want, listenerConf)
		}
	}
}

func TestWriteRuntimeArtifactsFullOverrideAndValidationGate(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	if _, err := dataStore.CreateApplication(ctx, model.Application{
		Name:    "Full",
		Mode:    model.ApplicationModeProtect,
		Enabled: true,
		Hosts:   []model.ApplicationHost{{Host: "full.example.test", IsPrimary: true}},
		Listeners: []model.ApplicationListener{
			{Port: 80, Protocol: model.ListenerProtocolHTTP, Enabled: true},
		},
		Upstreams: []model.ApplicationUpstream{{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true}},
	}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	fullConfig := `events {}
http {
    include /etc/litewaf/listeners/*.conf;
    init_by_lua_block { litewaf = require "litewaf" }
    init_worker_by_lua_block { litewaf.init_worker() }
    server {
        listen 80;
        location = /healthz { return 200 "ok"; }
        location = /metrics { content_by_lua_block { litewaf.metrics() } }
        location / {
            set $litewaf_upstream "";
            access_by_lua_block { litewaf.access() }
            header_filter_by_lua_block { litewaf.header_filter() }
            body_filter_by_lua_block { litewaf.body_filter() }
            log_by_lua_block { litewaf.log() }
            proxy_pass $litewaf_upstream;
        }
    }
}`
	if _, err := dataStore.SaveNginxConfigDraft(ctx, model.NginxConfigDraft{
		Mode:       model.NginxConfigModeFull,
		FullConfig: fullConfig,
		Validation: model.NginxValidationResult{Status: model.NginxValidationStatusUnchecked},
	}); err != nil {
		t.Fatalf("save full draft: %v", err)
	}
	base := t.TempDir()
	if _, err := WriteRuntimeArtifactsWithAdvancedNginx(ctx, dataStore, filepath.Join(base, "active.json"), "50m", ""); err == nil {
		t.Fatal("expected unavailable validation to block full override")
	}
	artifacts, err := WriteRuntimeArtifactsWithAdvancedNginx(ctx, dataStore, filepath.Join(base, "active.json"), "50m", writeExitScript(t, "nginx-ok", 0))
	if err != nil {
		t.Fatalf("write full override: %v", err)
	}
	if !artifacts.FullOverrideActive {
		t.Fatalf("expected full override artifact: %+v", artifacts)
	}
	written, err := os.ReadFile(filepath.Join(base, "nginx.conf"))
	if err != nil {
		t.Fatalf("read nginx.conf: %v", err)
	}
	if !bytes.Contains(written, []byte("include /etc/litewaf/listeners/*.conf;")) {
		t.Fatalf("full override was not written: %s", written)
	}
}

func writeExitScript(t *testing.T, name string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		path := filepath.Join(t.TempDir(), name+".bat")
		if err := os.WriteFile(path, []byte("@echo off\necho ok\nexit /b "+strconv.Itoa(exitCode)+"\n"), 0o600); err != nil {
			t.Fatalf("write script: %v", err)
		}
		return path
	}
	path := filepath.Join(t.TempDir(), name+".sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho ok\nexit "+strconv.Itoa(exitCode)+"\n"), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return path
}

func TestWriteRuntimeArtifactsFromConfigRestoresHistoricalListeners(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	cert, err := dataStore.CreateCertificate(ctx, model.Certificate{
		Name:        "Historical cert",
		Domains:     []string{"old.example.test"},
		CertPEM:     "OLD-CERTIFICATE-PEM",
		KeyPEM:      "OLD-PRIVATE-KEY-PEM",
		NotBefore:   time.Now().UTC().Add(-time.Hour),
		NotAfter:    time.Now().UTC().Add(time.Hour),
		Fingerprint: "historical-cert",
	})
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	config := ExtendedGatewayConfig{
		Version:     "historical",
		GeneratedAt: time.Now().UTC(),
		Applications: []GatewayApplication{
			{
				ID:      99,
				Name:    "Historical",
				Mode:    model.ApplicationModeProtect,
				Enabled: true,
				Hosts:   []string{"old.example.test"},
				Listeners: []GatewayApplicationListener{
					{Port: 8080, Protocol: model.ListenerProtocolHTTP, Enabled: true},
					{Port: 9443, Protocol: model.ListenerProtocolHTTPS, CertificateID: cert.ID, Enabled: true},
				},
				Upstreams: []GatewayApplicationUpstream{
					{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true},
				},
			},
		},
	}
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	base := t.TempDir()
	artifacts, err := WriteRuntimeArtifactsFromConfig(ctx, dataStore, payload, filepath.Join(base, "active.json"))
	if err != nil {
		t.Fatalf("write historical artifacts: %v", err)
	}
	if artifacts.ListenerCount != 2 || artifacts.HTTPSListenerCount != 1 || len(artifacts.CertificateIDs) != 1 {
		t.Fatalf("unexpected historical artifact summary: %+v", artifacts)
	}
	if artifacts.ClientMaxBodySize != "50m" {
		t.Fatalf("unexpected default body size artifact: %+v", artifacts)
	}
	listenerConf, err := os.ReadFile(filepath.Join(base, "listeners", "applications.conf"))
	if err != nil {
		t.Fatalf("read listener conf: %v", err)
	}
	if !bytes.Contains(listenerConf, []byte("listen 8080;")) || !bytes.Contains(listenerConf, []byte("listen 9443 ssl;")) {
		t.Fatalf("listener config did not restore historical ports: %s", listenerConf)
	}
	bodySizeConf, err := os.ReadFile(filepath.Join(base, "listeners", "body-size.conf"))
	if err != nil {
		t.Fatalf("read body-size conf: %v", err)
	}
	if string(bodySizeConf) != "# generated by litewaf publish; do not edit\nclient_max_body_size 50m;\n" {
		t.Fatalf("unexpected body-size config: %s", bodySizeConf)
	}
	keyPEM, err := os.ReadFile(filepath.Join(base, "certificates", "1.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(keyPEM) != "OLD-PRIVATE-KEY-PEM\n" {
		t.Fatalf("unexpected restored key material: %q", keyPEM)
	}
}

func TestWriteRuntimeArtifactsRejectsInvalidClientMaxBodySize(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()
	base := t.TempDir()

	if _, err := WriteRuntimeArtifactsWithClientMaxBodySize(ctx, dataStore, filepath.Join(base, "active.json"), "50m; lua_code_cache off;"); err == nil {
		t.Fatal("expected invalid client max body size to fail")
	}
}

func TestGenerateGatewayConfigEmptyState(t *testing.T) {
	ctx := context.Background()
	dataStore := store.NewMemoryStore()

	config, _, _, err := Generate(ctx, dataStore, "ruleset-0001")
	if err != nil {
		t.Fatalf("generate empty: %v", err)
	}
	if len(config.Applications) != 0 {
		t.Fatalf("expected no applications, got %d", len(config.Applications))
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
	if len(config.Applications) != 1 || len(config.Applications[0].Rules) != 1 {
		t.Fatalf("expected published package rule, got %+v", config.Applications)
	}
	published := config.Applications[0].Rules[0]
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
	if len(config.Applications) != 1 || len(config.Applications[0].Rules) != 1 {
		t.Fatalf("expected provider-origin rule in gateway config, got %+v", config.Applications)
	}
	published := config.Applications[0].Rules[0]
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
