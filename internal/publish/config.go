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
	"sort"
	"strings"
	"time"

	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/ipaccess"
	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
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
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Target         string `json:"target"`
	Action         string `json:"action"`
	Expression     string `json:"expression"`
	Score          int    `json:"score"`
	Module         string `json:"module,omitempty"`
	Category       string `json:"category,omitempty"`
	AttackType     string `json:"attack_type,omitempty"`
	Group          string `json:"group,omitempty"`
	Priority       int    `json:"priority,omitempty"`
	PackageID      string `json:"package_id,omitempty"`
	PackageVersion string `json:"package_version,omitempty"`
	PackageRuleID  string `json:"package_rule_id,omitempty"`
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
	Version         string                 `json:"version"`
	GeneratedAt     time.Time              `json:"generated_at"`
	Sites           []GatewaySite          `json:"sites"`
	IPAccessIndex   GatewayIPAccessIndex   `json:"ip_access_index"`
	RateLimits      []GatewayRateLimitRule `json:"rate_limits"`
	ProtectionRules []model.ProtectionRule `json:"protection_rules"`
}

type GatewayIPAccessEntry struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Target          string `json:"target"`
	NormalizedValue string `json:"normalized_value"`
	IPFamily        string `json:"ip_family"`
	PrefixLength    int    `json:"prefix_length"`
	SiteID          int64  `json:"site_id"`
	Priority        int    `json:"priority"`
}

type GatewayIPAccessIndex struct {
	Entries           map[string]GatewayIPAccessEntry `json:"entries"`
	Exact             GatewayIPAccessExact            `json:"exact"`
	CIDR              GatewayIPAccessCIDR             `json:"cidr"`
	CIDRPrefixLengths GatewayIPAccessPrefixLengths    `json:"cidr_prefix_lengths"`
}

type GatewayIPAccessExact struct {
	Allow map[string]map[string]string `json:"allow"`
	Block map[string]map[string]string `json:"block"`
}

type GatewayIPAccessCIDR struct {
	Allow map[string]map[string]map[string]map[string]string `json:"allow"`
	Block map[string]map[string]map[string]map[string]string `json:"block"`
}

type GatewayIPAccessPrefixLengths struct {
	Allow map[string]map[string][]int `json:"allow"`
	Block map[string]map[string][]int `json:"block"`
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
	ipAccessLists, err := dataStore.ListIPAccessListEntries(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	rateLimits, err := dataStore.ListRateLimitRules(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	uploadRules, err := dataStore.ListUploadProtectionRules(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	botRules, err := dataStore.ListBotProtectionRules(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	dynamicRules, err := dataStore.ListDynamicProtectionRules(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	protectionRules, err := dataStore.ListProtectionRules(ctx)
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
		IPAccessIndex:   emptyIPAccessIndex(),
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
				ID:             rule.ID,
				Name:           rule.Name,
				Type:           rule.Type,
				Target:         rule.Target,
				Action:         rule.Action,
				Expression:     rule.Expression,
				Score:          rule.Score,
				Module:         rule.Module,
				Category:       rule.Category,
				AttackType:     rule.AttackType,
				Group:          rule.Group,
				Priority:       rule.Priority,
				PackageID:      rule.PackageID,
				PackageVersion: rule.PackageVersion,
				PackageRuleID:  rule.PackageRuleID,
			})
		}
		config.Sites = append(config.Sites, gatewaySite)
	}
	seenLegacyProtectionRules := map[string]bool{}
	for _, item := range protectionRules {
		if item.Enabled {
			config.ProtectionRules = append(config.ProtectionRules, item)
		}
		if item.LegacyRef != "" {
			seenLegacyProtectionRules[item.LegacyRef] = true
		}
	}
	ipIndex, err := BuildIPAccessIndex(ipAccessLists)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	config.IPAccessIndex = ipIndex
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
		if !seenLegacyProtectionRules[protectionrules.LegacyRef("rate_limits", item.ID)] {
			config.ProtectionRules = append(config.ProtectionRules, CCProtectionFromRateLimit(item))
		}
	}
	for _, item := range uploadRules {
		if !item.Enabled {
			continue
		}
		if !seenLegacyProtectionRules[protectionrules.LegacyRef("upload_protection_rules", item.ID)] {
			config.ProtectionRules = append(config.ProtectionRules, UploadProtectionFromRule(item))
		}
	}
	for _, item := range botRules {
		if !item.Enabled {
			continue
		}
		if !seenLegacyProtectionRules[protectionrules.LegacyRef("bot_protection_rules", item.ID)] {
			config.ProtectionRules = append(config.ProtectionRules, BotProtectionFromRule(item))
		}
	}
	for _, item := range dynamicRules {
		if !item.Enabled {
			continue
		}
		if !seenLegacyProtectionRules[protectionrules.LegacyRef("dynamic_protection_rules", item.ID)] {
			config.ProtectionRules = append(config.ProtectionRules, DynamicProtectionFromRule(item))
		}
	}

	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	sum := sha256.Sum256(payload)
	return config, payload, hex.EncodeToString(sum[:]), nil
}

func CCProtectionFromRateLimit(item model.RateLimitRule) model.ProtectionRule {
	return protectionrules.FromRateLimit(item)
}

func UploadProtectionFromRule(item model.UploadProtectionRule) model.ProtectionRule {
	return protectionrules.FromUpload(item)
}

func BotProtectionFromRule(item model.BotProtectionRule) model.ProtectionRule {
	return protectionrules.FromBot(item)
}

func DynamicProtectionFromRule(item model.DynamicProtectionRule) model.ProtectionRule {
	return protectionrules.FromDynamic(item)
}

func dynamicProtectionConfig(item model.DynamicProtectionRule) model.ProtectionRuleDynamic {
	return protectionrules.DynamicConfig(item)
}

func protectionPriority(priority int) int {
	if priority <= 0 {
		return 100
	}
	return priority
}

func cloneStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func emptyIPAccessIndex() GatewayIPAccessIndex {
	return GatewayIPAccessIndex{
		Entries: map[string]GatewayIPAccessEntry{},
		Exact: GatewayIPAccessExact{
			Allow: map[string]map[string]string{},
			Block: map[string]map[string]string{},
		},
		CIDR: GatewayIPAccessCIDR{
			Allow: map[string]map[string]map[string]map[string]string{},
			Block: map[string]map[string]map[string]map[string]string{},
		},
		CIDRPrefixLengths: GatewayIPAccessPrefixLengths{
			Allow: map[string]map[string][]int{},
			Block: map[string]map[string][]int{},
		},
	}
}

func BuildIPAccessIndex(items []model.IPAccessListEntry) (GatewayIPAccessIndex, error) {
	index := emptyIPAccessIndex()
	prefixSets := map[string]map[string]map[string]map[int]bool{
		ipaccess.KindAllow: {},
		ipaccess.KindBlock: {},
	}
	for _, raw := range items {
		if !raw.Enabled {
			continue
		}
		item, err := ipaccess.Normalize(raw)
		if err != nil {
			return index, fmt.Errorf("ip access-list %d is invalid: %w", raw.ID, err)
		}
		if err := ipaccess.Validate(item); err != nil {
			return index, fmt.Errorf("ip access-list %d is invalid: %w", raw.ID, err)
		}
		entryID := fmt.Sprintf("%d", item.ID)
		scope := ipaccess.ScopeKey(item.SiteID)
		index.Entries[entryID] = GatewayIPAccessEntry{
			ID:              item.ID,
			Name:            item.Name,
			Kind:            item.Kind,
			Target:          item.Target,
			NormalizedValue: item.NormalizedValue,
			IPFamily:        item.IPFamily,
			PrefixLength:    item.PrefixLength,
			SiteID:          item.SiteID,
			Priority:        protectionPriority(item.Priority),
		}
		if item.Target == ipaccess.TargetIP {
			exact := index.Exact.Block
			if item.Kind == ipaccess.KindAllow {
				exact = index.Exact.Allow
			}
			ensureStringMap(exact, scope)
			if exact[scope][item.NormalizedValue] == "" {
				exact[scope][item.NormalizedValue] = entryID
			}
			continue
		}
		cidr := index.CIDR.Block
		if item.Kind == ipaccess.KindAllow {
			cidr = index.CIDR.Allow
		}
		ensureCIDRMap(cidr, scope, item.IPFamily, item.PrefixLength)
		prefixKey := fmt.Sprintf("%d", item.PrefixLength)
		if cidr[scope][item.IPFamily][prefixKey][item.NormalizedValue] == "" {
			cidr[scope][item.IPFamily][prefixKey][item.NormalizedValue] = entryID
		}
		ensurePrefixSet(prefixSets, item.Kind, scope, item.IPFamily)
		prefixSets[item.Kind][scope][item.IPFamily][item.PrefixLength] = true
	}
	index.CIDRPrefixLengths.Allow = prefixLists(prefixSets[ipaccess.KindAllow])
	index.CIDRPrefixLengths.Block = prefixLists(prefixSets[ipaccess.KindBlock])
	return index, nil
}

func ensureStringMap(target map[string]map[string]string, scope string) {
	if target[scope] == nil {
		target[scope] = map[string]string{}
	}
}

func ensureCIDRMap(target map[string]map[string]map[string]map[string]string, scope, family string, prefix int) {
	if target[scope] == nil {
		target[scope] = map[string]map[string]map[string]string{}
	}
	if target[scope][family] == nil {
		target[scope][family] = map[string]map[string]string{}
	}
	prefixKey := fmt.Sprintf("%d", prefix)
	if target[scope][family][prefixKey] == nil {
		target[scope][family][prefixKey] = map[string]string{}
	}
}

func ensurePrefixSet(target map[string]map[string]map[string]map[int]bool, kind, scope, family string) {
	if target[kind] == nil {
		target[kind] = map[string]map[string]map[int]bool{}
	}
	if target[kind][scope] == nil {
		target[kind][scope] = map[string]map[int]bool{}
	}
	if target[kind][scope][family] == nil {
		target[kind][scope][family] = map[int]bool{}
	}
}

func prefixLists(values map[string]map[string]map[int]bool) map[string]map[string][]int {
	out := map[string]map[string][]int{}
	for scope, byFamily := range values {
		if out[scope] == nil {
			out[scope] = map[string][]int{}
		}
		for family, set := range byFamily {
			list := make([]int, 0, len(set))
			for prefix := range set {
				list = append(list, prefix)
			}
			sort.Slice(list, func(i, j int) bool { return list[i] > list[j] })
			out[scope][family] = list
		}
	}
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
	ipAccessLists, err := dataStore.ListIPAccessListEntries(ctx)
	if err != nil {
		return err
	}
	rateLimits, err := dataStore.ListRateLimitRules(ctx)
	if err != nil {
		return err
	}
	uploadRules, err := dataStore.ListUploadProtectionRules(ctx)
	if err != nil {
		return err
	}
	botRules, err := dataStore.ListBotProtectionRules(ctx)
	if err != nil {
		return err
	}
	dynamicRules, err := dataStore.ListDynamicProtectionRules(ctx)
	if err != nil {
		return err
	}
	protectionRules, err := dataStore.ListProtectionRules(ctx)
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
		rule = attackmeta.NormalizeRule(rule)
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
		if err := validateAttackProtectionRule(rule); err != nil {
			return err
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
	for _, item := range ipAccessLists {
		if item.Enabled {
			normalized, err := ipaccess.Normalize(item)
			if err != nil {
				return fmt.Errorf("ip access-list %d is invalid: %w", item.ID, err)
			}
			if err := ipaccess.Validate(normalized); err != nil {
				return fmt.Errorf("ip access-list %d is invalid: %w", item.ID, err)
			}
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
	for _, item := range uploadRules {
		if item.Enabled {
			if err := validateUploadProtectionRule(item); err != nil {
				return err
			}
		}
	}
	for _, item := range botRules {
		if item.Enabled {
			if err := validateBotProtectionRule(item); err != nil {
				return err
			}
		}
	}
	for _, item := range dynamicRules {
		if item.Enabled {
			if err := validateDynamicProtectionRule(item); err != nil {
				return err
			}
		}
	}
	for _, item := range protectionRules {
		if item.Enabled {
			if err := protectionrules.Validate(item); err != nil {
				return fmt.Errorf("protection rule %d is invalid: %w", item.ID, err)
			}
		}
	}
	return nil
}

func validateAttackProtectionRule(rule model.Rule) error {
	if rule.Module != attackmeta.Module && rule.Category != attackmeta.Category {
		return nil
	}
	if rule.Module != attackmeta.Module || rule.Category != attackmeta.Category {
		return fmt.Errorf("rule %d attack protection metadata is incomplete", rule.ID)
	}
	if !attackmeta.ValidAttackType(rule.AttackType) {
		return fmt.Errorf("rule %d attack protection attack_type is unsupported", rule.ID)
	}
	if rule.Action != "log-only" && rule.Action != "block" {
		return fmt.Errorf("rule %d attack protection action is unsupported", rule.ID)
	}
	if rule.Priority <= 0 {
		return fmt.Errorf("rule %d attack protection priority must be positive", rule.ID)
	}
	if rule.ID <= 0 {
		return fmt.Errorf("rule %d attack protection rule reference is invalid", rule.ID)
	}
	return nil
}

func validateUploadProtectionRule(item model.UploadProtectionRule) error {
	if item.Name == "" {
		return fmt.Errorf("upload protection rule %d name is required", item.ID)
	}
	if item.Path == "" || !strings.HasPrefix(item.Path, "/") {
		return fmt.Errorf("upload protection rule %d path must start with /", item.ID)
	}
	if item.PathMatch != "" && item.PathMatch != "exact" && item.PathMatch != "prefix" {
		return fmt.Errorf("upload protection rule %d path_match is unsupported", item.ID)
	}
	for _, method := range item.Methods {
		if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" && method != "HEAD" && method != "OPTIONS" {
			return fmt.Errorf("upload protection rule %d method is unsupported", item.ID)
		}
	}
	if len(item.Extensions) == 0 && item.MaxBytes <= 0 {
		return fmt.Errorf("upload protection rule %d requires extensions or max_bytes", item.ID)
	}
	for _, extension := range item.Extensions {
		if extension == "" || strings.ContainsAny(extension, `/\`) || strings.Contains(extension, "..") {
			return fmt.Errorf("upload protection rule %d extension is invalid", item.ID)
		}
	}
	if item.MaxBytes < 0 {
		return fmt.Errorf("upload protection rule %d max_bytes cannot be negative", item.ID)
	}
	if item.Action != "block" && item.Action != "log-only" {
		return fmt.Errorf("upload protection rule %d action is unsupported", item.ID)
	}
	if item.Priority < 0 {
		return fmt.Errorf("upload protection rule %d priority cannot be negative", item.ID)
	}
	return nil
}

func validateBotProtectionRule(item model.BotProtectionRule) error {
	if item.Name == "" {
		return fmt.Errorf("bot protection rule %d name is required", item.ID)
	}
	if item.Path == "" || !strings.HasPrefix(item.Path, "/") {
		return fmt.Errorf("bot protection rule %d path must start with /", item.ID)
	}
	if item.PathMatch != "" && item.PathMatch != "exact" && item.PathMatch != "prefix" {
		return fmt.Errorf("bot protection rule %d path_match is unsupported", item.ID)
	}
	for _, method := range item.Methods {
		if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" && method != "HEAD" && method != "OPTIONS" {
			return fmt.Errorf("bot protection rule %d method is unsupported", item.ID)
		}
	}
	if item.ChallengeMode != "js-challenge" {
		return fmt.Errorf("bot protection rule %d challenge mode is unsupported", item.ID)
	}
	if item.VerifyTTL <= 0 || item.VerifyTTL > 86400 {
		return fmt.Errorf("bot protection rule %d verify_ttl_sec is invalid", item.ID)
	}
	if item.FailureAction != "block" && item.FailureAction != "log-only" {
		return fmt.Errorf("bot protection rule %d failure_action is unsupported", item.ID)
	}
	if item.Priority < 0 {
		return fmt.Errorf("bot protection rule %d priority cannot be negative", item.ID)
	}
	return nil
}

func validateDynamicProtectionRule(item model.DynamicProtectionRule) error {
	if item.Name == "" {
		return fmt.Errorf("dynamic protection rule %d name is required", item.ID)
	}
	if item.Category != "dynamic-token" && item.Category != "page-mutation" && item.Category != "waiting-room" {
		return fmt.Errorf("dynamic protection rule %d category is unsupported", item.ID)
	}
	if item.Path == "" || !strings.HasPrefix(item.Path, "/") {
		return fmt.Errorf("dynamic protection rule %d path must start with /", item.ID)
	}
	if item.PathMatch != "" && item.PathMatch != "exact" && item.PathMatch != "prefix" {
		return fmt.Errorf("dynamic protection rule %d path_match is unsupported", item.ID)
	}
	for _, method := range item.Methods {
		if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" && method != "HEAD" && method != "OPTIONS" {
			return fmt.Errorf("dynamic protection rule %d method is unsupported", item.ID)
		}
	}
	if item.Priority < 0 {
		return fmt.Errorf("dynamic protection rule %d priority cannot be negative", item.ID)
	}
	switch item.Category {
	case "dynamic-token":
		if item.TokenTTL <= 0 || item.TokenTTL > 86400 {
			return fmt.Errorf("dynamic protection rule %d token_ttl_sec is invalid", item.ID)
		}
		if item.TokenPlacement != "cookie" && item.TokenPlacement != "header" && item.TokenPlacement != "query" {
			return fmt.Errorf("dynamic protection rule %d token_placement is unsupported", item.ID)
		}
		if item.FailureAction != "block" && item.FailureAction != "log-only" {
			return fmt.Errorf("dynamic protection rule %d failure_action is unsupported", item.ID)
		}
	case "page-mutation":
		if item.MutationMarker != "head-end" && item.MutationMarker != "body-end" {
			return fmt.Errorf("dynamic protection rule %d mutation_marker is unsupported", item.ID)
		}
		if item.MutationMaxBytes <= 0 || item.MutationMaxBytes > 1048576 {
			return fmt.Errorf("dynamic protection rule %d mutation_max_bytes is invalid", item.ID)
		}
	case "waiting-room":
		if item.QueueCapacity <= 0 || item.QueueCapacity > 100000 {
			return fmt.Errorf("dynamic protection rule %d queue_capacity is invalid", item.ID)
		}
		if item.AdmissionTTL <= 0 || item.AdmissionTTL > 86400 {
			return fmt.Errorf("dynamic protection rule %d admission_ttl_sec is invalid", item.ID)
		}
		if item.RetryInterval <= 0 || item.RetryInterval > 86400 {
			return fmt.Errorf("dynamic protection rule %d retry_interval_sec is invalid", item.ID)
		}
		if item.OverflowAction != "waiting-room" && item.OverflowAction != "block" && item.OverflowAction != "log-only" {
			return fmt.Errorf("dynamic protection rule %d overflow_action is unsupported", item.ID)
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
