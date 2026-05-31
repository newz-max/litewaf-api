package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"litewaf-api/internal/model"
	"litewaf-api/internal/store"
)

type GatewayConfig struct {
	Version     string        `json:"version"`
	GeneratedAt time.Time     `json:"generated_at"`
	Sites       []GatewaySite `json:"sites"`
}

type GatewaySite struct {
	ID       int64         `json:"id"`
	Name     string        `json:"name"`
	Host     string        `json:"host"`
	Upstream string        `json:"upstream"`
	Mode     string        `json:"mode"`
	Rules    []GatewayRule `json:"rules"`
	Policy   GatewayPolicy `json:"policy"`
}

type GatewayRule struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Target     string `json:"target"`
	Action     string `json:"action"`
	Expression string `json:"expression"`
	Score      int    `json:"score"`
}

type GatewayAccessListEntry struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Value  string `json:"value"`
	Action string `json:"action"`
	SiteID int64  `json:"site_id"`
}

type GatewayRateLimitRule struct {
	ID                 int64    `json:"id"`
	Name               string   `json:"name"`
	Scope              string   `json:"scope"`
	MatchValue         string   `json:"match_value"`
	PathMatch          string   `json:"path_match"`
	Methods            []string `json:"methods"`
	Threshold          int      `json:"threshold"`
	WindowSec          int      `json:"window_sec"`
	Action             string   `json:"action"`
	CCAction           string   `json:"cc_action"`
	BanDuration        int      `json:"ban_duration_sec"`
	ViolationThreshold int      `json:"violation_threshold"`
	ViolationWindowSec int      `json:"violation_window_sec"`
	SiteID             int64    `json:"site_id"`
}

type GatewayPolicy struct {
	ID                         int64    `json:"id"`
	Name                       string   `json:"name"`
	RiskThreshold              int      `json:"risk_threshold"`
	DefaultAction              string   `json:"default_action"`
	NormalizationEnabled       bool     `json:"normalization_enabled"`
	NormalizationDecodePasses  int      `json:"normalization_decode_passes"`
	NormalizationMaxValueBytes int      `json:"normalization_max_value_bytes"`
	BodyInspectionEnabled      bool     `json:"body_inspection_enabled"`
	BodyInspectionContentTypes []string `json:"body_inspection_content_types"`
	BodyInspectionPathPrefixes []string `json:"body_inspection_path_prefixes"`
	BodyInspectionMaxBytes     int      `json:"body_inspection_max_bytes"`
	OversizedBodyAction        string   `json:"oversized_body_action"`
	UploadInspectionEnabled    bool     `json:"upload_inspection_enabled"`
	UploadMaxBytes             int      `json:"upload_max_bytes"`
	UploadSizeAction           string   `json:"upload_size_action"`
	DynamicBanEnabled          bool     `json:"dynamic_ban_enabled"`
	DynamicBanDurationSec      int      `json:"dynamic_ban_duration_sec"`
	DynamicBanScoreThreshold   int      `json:"dynamic_ban_score_threshold"`
	DynamicBanTriggerCount     int      `json:"dynamic_ban_trigger_count"`
	DynamicBanWindowSec        int      `json:"dynamic_ban_window_sec"`
}

type ExtendedGatewayConfig struct {
	Version         string                   `json:"version"`
	GeneratedAt     time.Time                `json:"generated_at"`
	Sites           []GatewaySite            `json:"sites"`
	AccessLists     []GatewayAccessListEntry `json:"access_lists"`
	RateLimits      []GatewayRateLimitRule   `json:"rate_limits"`
	ProtectionRules []model.ProtectionRule   `json:"protection_rules"`
}

func Generate(ctx context.Context, dataStore store.Store, version string) (GatewayConfig, []byte, string, error) {
	config, payload, checksum, err := GenerateExtended(ctx, dataStore, version)
	return GatewayConfig{
		Version:     config.Version,
		GeneratedAt: config.GeneratedAt,
		Sites:       config.Sites,
	}, payload, checksum, err
}

func GenerateExtended(ctx context.Context, dataStore store.Store, version string) (ExtendedGatewayConfig, []byte, string, error) {
	if err := Validate(ctx, dataStore); err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	sites, err := dataStore.ListSites(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	rules, err := dataStore.ListRules(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	policies, err := dataStore.ListPolicies(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	accessLists, err := dataStore.ListAccessListEntries(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	rateLimits, err := dataStore.ListRateLimitRules(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}

	rulesByID := map[int64]model.Rule{}
	for _, rule := range rules {
		if rule.Enabled {
			rulesByID[rule.ID] = rule
		}
	}

	siteRules := map[int64]map[int64]model.Rule{}
	sitePolicies := map[int64]model.Policy{}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		for _, siteID := range policy.SiteIDs {
			if siteRules[siteID] == nil {
				siteRules[siteID] = map[int64]model.Rule{}
			}
			for _, ruleID := range policy.RuleIDs {
				if rule, ok := rulesByID[ruleID]; ok {
					siteRules[siteID][rule.ID] = rule
				}
			}
			if _, exists := sitePolicies[siteID]; !exists {
				sitePolicies[siteID] = defaultPolicy(policy)
			}
		}
	}

	config := ExtendedGatewayConfig{
		Version:         version,
		GeneratedAt:     time.Now().UTC(),
		Sites:           []GatewaySite{},
		AccessLists:     []GatewayAccessListEntry{},
		RateLimits:      []GatewayRateLimitRule{},
		ProtectionRules: []model.ProtectionRule{},
	}
	for _, site := range sites {
		if !site.Enabled {
			continue
		}
		gatewaySite := GatewaySite{
			ID:       site.ID,
			Name:     site.Name,
			Host:     site.Host,
			Upstream: site.Upstream,
			Mode:     site.Mode,
			Rules:    []GatewayRule{},
			Policy:   gatewayPolicy(sitePolicies[site.ID]),
		}
		for _, rule := range siteRules[site.ID] {
			gatewaySite.Rules = append(gatewaySite.Rules, GatewayRule{
				ID:         rule.ID,
				Name:       rule.Name,
				Type:       rule.Type,
				Target:     rule.Target,
				Action:     rule.Action,
				Expression: rule.Expression,
				Score:      rule.Score,
			})
		}
		config.Sites = append(config.Sites, gatewaySite)
	}
	for _, item := range accessLists {
		if !item.Enabled {
			continue
		}
		config.AccessLists = append(config.AccessLists, GatewayAccessListEntry{
			ID:     item.ID,
			Name:   item.Name,
			Kind:   item.Kind,
			Target: item.Target,
			Value:  item.Value,
			Action: item.Action,
			SiteID: item.SiteID,
		})
	}
	for _, item := range rateLimits {
		if !item.Enabled {
			continue
		}
		config.RateLimits = append(config.RateLimits, GatewayRateLimitRule{
			ID:                 item.ID,
			Name:               item.Name,
			Scope:              item.Scope,
			MatchValue:         item.MatchValue,
			PathMatch:          item.PathMatch,
			Methods:            cloneStrings(item.Methods),
			Threshold:          item.Threshold,
			WindowSec:          item.WindowSec,
			Action:             item.Action,
			CCAction:           item.CCAction,
			BanDuration:        item.BanDuration,
			ViolationThreshold: item.ViolationThreshold,
			ViolationWindowSec: item.ViolationWindowSec,
			SiteID:             item.SiteID,
		})
		config.ProtectionRules = append(config.ProtectionRules, CCProtectionFromRateLimit(item))
	}

	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	sum := sha256.Sum256(payload)
	return config, payload, hex.EncodeToString(sum[:]), nil
}

func CCProtectionFromRateLimit(item model.RateLimitRule) model.ProtectionRule {
	path, pathMatch := ccProtectionPath(item)
	return model.ProtectionRule{
		ID:       item.ID,
		Name:     item.Name,
		Module:   "cc-protection",
		Category: "rate-limit",
		SiteID:   item.SiteID,
		Enabled:  item.Enabled,
		Priority: 100,
		Match: model.ProtectionRuleMatch{
			Path:      path,
			PathMatch: pathMatch,
			Methods:   cloneStrings(item.Methods),
		},
		Limit: model.ProtectionRuleLimit{
			Counter:        ccProtectionCounter(item.Scope),
			Threshold:      item.Threshold,
			WindowSec:      item.WindowSec,
			BanDurationSec: item.BanDuration,
		},
		Action: model.ProtectionRuleAction{
			Type: ccProtectionAction(item),
		},
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	}
}

func ccProtectionPath(item model.RateLimitRule) (string, string) {
	pathMatch := item.PathMatch
	if pathMatch == "" {
		pathMatch = "exact"
	}
	if item.MatchValue != "" {
		return item.MatchValue, pathMatch
	}
	if item.Scope == "site" || item.Scope == "ip" {
		if item.PathMatch == "" {
			pathMatch = "prefix"
		}
		return "/", pathMatch
	}
	return "/", "prefix"
}

func ccProtectionCounter(scope string) string {
	switch scope {
	case "ip":
		return "client_ip"
	case "uri":
		return "client_ip_path"
	case "site":
		return "global"
	default:
		return "client_ip"
	}
}

func ccProtectionAction(item model.RateLimitRule) string {
	if item.CCAction != "" {
		return item.CCAction
	}
	if item.Action == "" {
		return "rate-limit"
	}
	return item.Action
}

func cloneStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func Validate(ctx context.Context, dataStore store.Store) error {
	sites, err := dataStore.ListSites(ctx)
	if err != nil {
		return err
	}
	rules, err := dataStore.ListRules(ctx)
	if err != nil {
		return err
	}
	policies, err := dataStore.ListPolicies(ctx)
	if err != nil {
		return err
	}
	accessLists, err := dataStore.ListAccessListEntries(ctx)
	if err != nil {
		return err
	}
	rateLimits, err := dataStore.ListRateLimitRules(ctx)
	if err != nil {
		return err
	}

	siteIDs := map[int64]bool{}
	for _, site := range sites {
		if site.Enabled {
			siteIDs[site.ID] = true
			if site.Host == "" || site.Upstream == "" {
				return errors.New("enabled site must have host and upstream")
			}
		}
	}
	ruleIDs := map[int64]bool{}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		ruleIDs[rule.ID] = true
		if rule.Expression == "" {
			return fmt.Errorf("rule %d expression is required", rule.ID)
		}
		if _, err := regexp.Compile(rule.Expression); err != nil {
			if rule.Target != "upload_size" {
				return fmt.Errorf("rule %d expression is invalid: %w", rule.ID, err)
			}
		}
		if rule.Target == "upload_size" {
			var size int
			if _, err := fmt.Sscanf(rule.Expression, "%d", &size); err != nil || size < 0 {
				return fmt.Errorf("rule %d upload_size expression is invalid", rule.ID)
			}
		}
	}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		policy = defaultPolicy(policy)
		if policy.RiskThreshold <= 0 || policy.NormalizationDecodePasses <= 0 || policy.NormalizationMaxValueBytes <= 0 ||
			policy.BodyInspectionMaxBytes <= 0 || policy.UploadMaxBytes <= 0 || policy.DynamicBanDurationSec <= 0 ||
			policy.DynamicBanScoreThreshold <= 0 || policy.DynamicBanTriggerCount <= 0 || policy.DynamicBanWindowSec <= 0 {
			return fmt.Errorf("policy %d advanced protection settings are invalid", policy.ID)
		}
		for _, siteID := range policy.SiteIDs {
			if !siteIDs[siteID] {
				return fmt.Errorf("policy %d references missing or disabled site %d", policy.ID, siteID)
			}
		}
		for _, ruleID := range policy.RuleIDs {
			if !ruleIDs[ruleID] {
				return fmt.Errorf("policy %d references missing or disabled rule %d", policy.ID, ruleID)
			}
		}
	}
	for _, item := range accessLists {
		if item.Enabled && (item.Value == "" || item.Kind == "" || item.Target == "" || item.Action == "") {
			return fmt.Errorf("access list %d is incomplete", item.ID)
		}
	}
	for _, item := range rateLimits {
		if item.Enabled && (item.Threshold <= 0 || item.WindowSec <= 0 || item.Action == "" || item.Scope == "") {
			return fmt.Errorf("rate limit %d is incomplete", item.ID)
		}
		if item.Enabled && item.ViolationThreshold > 0 && (item.ViolationWindowSec <= 0 || item.BanDuration <= 0) {
			return fmt.Errorf("rate limit %d repeated violation settings are incomplete", item.ID)
		}
	}
	return nil
}

func gatewayPolicy(policy model.Policy) GatewayPolicy {
	policy = defaultPolicy(policy)
	return GatewayPolicy{
		ID:                         policy.ID,
		Name:                       policy.Name,
		RiskThreshold:              policy.RiskThreshold,
		DefaultAction:              policy.DefaultAction,
		NormalizationEnabled:       policy.NormalizationEnabled,
		NormalizationDecodePasses:  policy.NormalizationDecodePasses,
		NormalizationMaxValueBytes: policy.NormalizationMaxValueBytes,
		BodyInspectionEnabled:      policy.BodyInspectionEnabled,
		BodyInspectionContentTypes: policy.BodyInspectionContentTypes,
		BodyInspectionPathPrefixes: policy.BodyInspectionPathPrefixes,
		BodyInspectionMaxBytes:     policy.BodyInspectionMaxBytes,
		OversizedBodyAction:        policy.OversizedBodyAction,
		UploadInspectionEnabled:    policy.UploadInspectionEnabled,
		UploadMaxBytes:             policy.UploadMaxBytes,
		UploadSizeAction:           policy.UploadSizeAction,
		DynamicBanEnabled:          policy.DynamicBanEnabled,
		DynamicBanDurationSec:      policy.DynamicBanDurationSec,
		DynamicBanScoreThreshold:   policy.DynamicBanScoreThreshold,
		DynamicBanTriggerCount:     policy.DynamicBanTriggerCount,
		DynamicBanWindowSec:        policy.DynamicBanWindowSec,
	}
}

func defaultPolicy(policy model.Policy) model.Policy {
	if policy.RiskThreshold == 0 {
		policy.RiskThreshold = 100
	}
	if policy.DefaultAction == "" {
		policy.DefaultAction = "block"
	}
	if policy.NormalizationDecodePasses == 0 {
		policy.NormalizationDecodePasses = 2
	}
	if policy.NormalizationMaxValueBytes == 0 {
		policy.NormalizationMaxValueBytes = 4096
	}
	if policy.BodyInspectionMaxBytes == 0 {
		policy.BodyInspectionMaxBytes = 65536
	}
	if policy.OversizedBodyAction == "" {
		policy.OversizedBodyAction = "log-only"
	}
	if policy.UploadMaxBytes == 0 {
		policy.UploadMaxBytes = 10485760
	}
	if policy.UploadSizeAction == "" {
		policy.UploadSizeAction = "block"
	}
	if policy.DynamicBanDurationSec == 0 {
		policy.DynamicBanDurationSec = 300
	}
	if policy.DynamicBanScoreThreshold == 0 {
		policy.DynamicBanScoreThreshold = 200
	}
	if policy.DynamicBanTriggerCount == 0 {
		policy.DynamicBanTriggerCount = 3
	}
	if policy.DynamicBanWindowSec == 0 {
		policy.DynamicBanWindowSec = 60
	}
	return policy
}

func WriteAtomic(path string, payload []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
