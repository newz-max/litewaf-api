package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/gatewayconfig"
	"litewaf-api/internal/ipaccess"
	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
	"litewaf-api/internal/store"
)

type GatewayConfig struct {
	Version      string               `json:"version"`
	GeneratedAt  time.Time            `json:"generated_at"`
	Applications []GatewayApplication `json:"applications"`
}

type GatewayApplication struct {
	ID          int64                         `json:"id"`
	Name        string                        `json:"name"`
	Mode        string                        `json:"mode"`
	Enabled     bool                          `json:"enabled"`
	Hosts       []string                      `json:"hosts"`
	Listeners   []GatewayApplicationListener  `json:"listeners"`
	Upstreams   []GatewayApplicationUpstream  `json:"upstreams"`
	ProxyConfig *model.ApplicationProxyConfig `json:"proxy_config,omitempty"`
	Rules       []GatewayRule                 `json:"rules"`
	Policy      GatewayPolicy                 `json:"policy"`
}

type GatewayApplicationListener struct {
	Port          int    `json:"port"`
	Protocol      string `json:"protocol"`
	CertificateID int64  `json:"certificate_id,omitempty"`
	Enabled       bool   `json:"enabled"`
}

type GatewayApplicationUpstream struct {
	Name    string `json:"name,omitempty"`
	URL     string `json:"url"`
	Weight  int    `json:"weight"`
	Enabled bool   `json:"enabled"`
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
	SiteID             int64    `json:"application_id"`
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
	Applications    []GatewayApplication   `json:"applications"`
	IPAccessIndex   GatewayIPAccessIndex   `json:"ip_access_index"`
	RateLimits      []GatewayRateLimitRule `json:"rate_limits"`
	ProtectionRules []model.ProtectionRule `json:"protection_rules"`
}

type ApplicationValidationIssue struct {
	Severity        string `json:"severity"`
	Category        string `json:"category"`
	ApplicationID   int64  `json:"application_id,omitempty"`
	ApplicationName string `json:"application_name,omitempty"`
	Host            string `json:"host,omitempty"`
	Port            int    `json:"port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	CertificateID   int64  `json:"certificate_id,omitempty"`
	Message         string `json:"message"`
}

type GatewayListenerDeployment struct {
	Mode            string `json:"mode"`
	BridgePortRange string `json:"bridge_port_range,omitempty"`
}

type RuntimeArtifacts struct {
	ListenerConfigPath  string                      `json:"listener_config_path"`
	BodySizeConfigPath  string                      `json:"body_size_config_path"`
	SnippetConfigDir    string                      `json:"snippet_config_dir,omitempty"`
	NginxConfigPath     string                      `json:"nginx_config_path,omitempty"`
	ClientMaxBodySize   string                      `json:"client_max_body_size"`
	CertificateDir      string                      `json:"certificate_dir"`
	ListenerCount       int                         `json:"listener_count"`
	HTTPSListenerCount  int                         `json:"https_listener_count"`
	CertificateIDs      []int64                     `json:"certificate_ids"`
	AdvancedConfig      bool                        `json:"advanced_config"`
	FullOverrideActive  bool                        `json:"full_override_active"`
	Validation          model.NginxValidationResult `json:"validation,omitempty"`
	RuntimeArtifactJSON string                      `json:"-"`
}

type RuntimeArtifactSnapshot struct {
	Files []RuntimeArtifactFile `json:"files"`
}

type RuntimeArtifactFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    uint32 `json:"mode,omitempty"`
}

type AdvancedNginxReview struct {
	HasAdvancedChanges bool                        `json:"has_advanced_changes"`
	Mode               string                      `json:"mode"`
	Warnings           []string                    `json:"warnings"`
	Validation         model.NginxValidationResult `json:"validation"`
	Diff               string                      `json:"diff"`
}

type GatewayIPAccessEntry struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Target          string `json:"target"`
	NormalizedValue string `json:"normalized_value"`
	IPFamily        string `json:"ip_family"`
	PrefixLength    int    `json:"prefix_length"`
	SiteID          int64  `json:"application_id"`
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
		Version:      config.Version,
		GeneratedAt:  config.GeneratedAt,
		Applications: config.Applications,
	}, payload, checksum, err
}

func GenerateExtended(ctx context.Context, dataStore store.Store, version string) (ExtendedGatewayConfig, []byte, string, error) {
	if err := Validate(ctx, dataStore); err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	applications, err := dataStore.ListApplications(ctx)
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	if len(applications) == 0 {
		sites, err := dataStore.ListSites(ctx)
		if err != nil {
			return ExtendedGatewayConfig{}, nil, "", err
		}
		applications = ApplicationsFromSites(sites)
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
		Applications:    []GatewayApplication{},
		IPAccessIndex:   emptyIPAccessIndex(),
		RateLimits:      []GatewayRateLimitRule{},
		ProtectionRules: []model.ProtectionRule{},
	}
	for _, application := range applications {
		if !application.Enabled {
			continue
		}
		gatewayApplication := GatewayApplication{
			ID:          application.ID,
			Name:        application.Name,
			Mode:        application.Mode,
			Enabled:     application.Enabled,
			Hosts:       gatewayHosts(application.Hosts),
			Listeners:   gatewayListeners(application.Listeners),
			Upstreams:   gatewayUpstreams(application.Upstreams),
			ProxyConfig: cloneApplicationProxyConfig(application.ProxyConfig),
			Rules:       []GatewayRule{},
			Policy:      gatewayPolicy(sitePolicies[application.ID]),
		}
		for _, rule := range siteRules[application.ID] {
			gatewayApplication.Rules = append(gatewayApplication.Rules, GatewayRule{
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
		config.Applications = append(config.Applications, gatewayApplication)
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

func ApplicationsFromSites(sites []model.Site) []model.Application {
	applications := make([]model.Application, 0, len(sites))
	for _, site := range sites {
		app := model.Application{
			ID:      site.ID,
			Name:    site.Name,
			Mode:    site.Mode,
			Enabled: site.Enabled,
			Hosts: []model.ApplicationHost{
				{ApplicationID: site.ID, Host: site.Host, IsPrimary: true},
			},
			Listeners: []model.ApplicationListener{
				{ApplicationID: site.ID, Port: 80, Protocol: model.ListenerProtocolHTTP, Enabled: true},
			},
			Upstreams: []model.ApplicationUpstream{
				{ApplicationID: site.ID, Name: "primary", URL: site.Upstream, Weight: 1, Enabled: true},
			},
			CreatedAt: site.CreatedAt,
			UpdatedAt: site.UpdatedAt,
		}
		model.NormalizeApplication(&app)
		applications = append(applications, app)
	}
	return applications
}

func gatewayHosts(hosts []model.ApplicationHost) []string {
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host.Host != "" {
			out = append(out, host.Host)
		}
	}
	return out
}

func gatewayListeners(listeners []model.ApplicationListener) []GatewayApplicationListener {
	out := make([]GatewayApplicationListener, 0, len(listeners))
	for _, listener := range listeners {
		out = append(out, GatewayApplicationListener{
			Port:          listener.Port,
			Protocol:      listener.Protocol,
			CertificateID: listener.CertificateID,
			Enabled:       listener.Enabled,
		})
	}
	return out
}

func gatewayUpstreams(upstreams []model.ApplicationUpstream) []GatewayApplicationUpstream {
	out := make([]GatewayApplicationUpstream, 0, len(upstreams))
	for _, upstream := range upstreams {
		out = append(out, GatewayApplicationUpstream{
			Name:    upstream.Name,
			URL:     upstream.URL,
			Weight:  upstream.Weight,
			Enabled: upstream.Enabled,
		})
	}
	return out
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

func ValidateApplicationReadiness(ctx context.Context, dataStore store.Store) ([]ApplicationValidationIssue, error) {
	return ValidateApplicationReadinessWithDeployment(ctx, dataStore, GatewayListenerDeployment{Mode: "host-network"})
}

func ValidateApplicationReadinessWithDeployment(ctx context.Context, dataStore store.Store, deployment GatewayListenerDeployment) ([]ApplicationValidationIssue, error) {
	applications, err := dataStore.ListApplications(ctx)
	if err != nil {
		return nil, err
	}
	if len(applications) == 0 {
		sites, err := dataStore.ListSites(ctx)
		if err != nil {
			return nil, err
		}
		applications = ApplicationsFromSites(sites)
	}
	certificates, err := dataStore.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	certificateByID := map[int64]model.Certificate{}
	for _, cert := range certificates {
		certificateByID[cert.ID] = cert
	}
	certificateExists := func(id int64) bool {
		_, ok := certificateByID[id]
		return ok
	}
	policies, err := dataStore.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	ipAccessLists, err := dataStore.ListIPAccessListEntries(ctx)
	if err != nil {
		return nil, err
	}
	rateLimits, err := dataStore.ListRateLimitRules(ctx)
	if err != nil {
		return nil, err
	}
	uploadRules, err := dataStore.ListUploadProtectionRules(ctx)
	if err != nil {
		return nil, err
	}
	botRules, err := dataStore.ListBotProtectionRules(ctx)
	if err != nil {
		return nil, err
	}
	dynamicRules, err := dataStore.ListDynamicProtectionRules(ctx)
	if err != nil {
		return nil, err
	}
	protectionRules, err := dataStore.ListProtectionRules(ctx)
	if err != nil {
		return nil, err
	}

	mode, bridgeRanges := normalizeListenerDeployment(deployment)
	var issues []ApplicationValidationIssue
	applicationByID := map[int64]model.Application{}
	for _, application := range applications {
		applicationByID[application.ID] = application
	}
	issues = append(issues, disabledReferenceIssues(applicationByID, policies, protectionRules, rateLimits, ipAccessLists, uploadRules, botRules, dynamicRules)...)
	listenerOwners := map[string]listenerOwner{}
	for _, application := range applications {
		if !application.Enabled {
			continue
		}
		if countEnabledListeners(application.Listeners) == 0 {
			issues = append(issues, ApplicationValidationIssue{
				Severity:        "error",
				Category:        "no-enabled-listener",
				ApplicationID:   application.ID,
				ApplicationName: application.Name,
				Message:         fmt.Sprintf("application %d has no enabled listener", application.ID),
			})
		}
		if countEnabledUpstreams(application.Upstreams) == 0 {
			issues = append(issues, ApplicationValidationIssue{
				Severity:        "error",
				Category:        "no-enabled-upstream",
				ApplicationID:   application.ID,
				ApplicationName: application.Name,
				Message:         fmt.Sprintf("application %d has no enabled upstream", application.ID),
			})
		}
		if err := model.ValidateApplication(application, certificateExists); err != nil {
			issues = append(issues, ApplicationValidationIssue{
				Severity:        "error",
				Category:        "application-validation",
				ApplicationID:   application.ID,
				ApplicationName: application.Name,
				Message:         fmt.Sprintf("application %d is invalid: %v", application.ID, err),
			})
			continue
		}
		hosts := applicationHostSet(application.Hosts)
		for _, listener := range application.Listeners {
			if !listener.Enabled {
				continue
			}
			for host := range hosts {
				key := fmt.Sprintf("%s/%d/%s", host, listener.Port, listener.Protocol)
				if owner, ok := listenerOwners[key]; ok {
					issues = append(issues, ApplicationValidationIssue{
						Severity:        "error",
						Category:        "listener-port-conflict",
						ApplicationID:   application.ID,
						ApplicationName: application.Name,
						Host:            host,
						Port:            listener.Port,
						Protocol:        listener.Protocol,
						Message:         fmt.Sprintf("listener %s is already used by application %d (%s)", key, owner.ApplicationID, owner.ApplicationName),
					})
				} else {
					listenerOwners[key] = listenerOwner{ApplicationID: application.ID, ApplicationName: application.Name}
				}
			}
			if mode == "bridge-range" && !portInRanges(listener.Port, bridgeRanges) {
				issues = append(issues, ApplicationValidationIssue{
					Severity:        "error",
					Category:        "deployment-mode-port",
					ApplicationID:   application.ID,
					ApplicationName: application.Name,
					Port:            listener.Port,
					Protocol:        listener.Protocol,
					Message:         fmt.Sprintf("listener %d/%s is outside configured bridge port range %s", listener.Port, listener.Protocol, rangeSummary(bridgeRanges)),
				})
			}
			if listener.Protocol != model.ListenerProtocolHTTPS {
				continue
			}
			cert, ok := certificateByID[listener.CertificateID]
			if !ok {
				issues = append(issues, ApplicationValidationIssue{
					Severity:        "error",
					Category:        "missing-certificate",
					ApplicationID:   application.ID,
					ApplicationName: application.Name,
					Port:            listener.Port,
					Protocol:        listener.Protocol,
					CertificateID:   listener.CertificateID,
					Message:         fmt.Sprintf("https listener %d for application %d references missing certificate %d", listener.Port, application.ID, listener.CertificateID),
				})
				continue
			}
			if !certificateCoversAnyHost(cert.Domains, hosts) {
				issues = append(issues, ApplicationValidationIssue{
					Severity:        "warning",
					Category:        "certificate-domain-mismatch",
					ApplicationID:   application.ID,
					ApplicationName: application.Name,
					Port:            listener.Port,
					Protocol:        listener.Protocol,
					CertificateID:   listener.CertificateID,
					Message:         fmt.Sprintf("certificate %d does not cover any host for application %d", listener.CertificateID, application.ID),
				})
			}
		}
	}
	return issues, nil
}

type listenerOwner struct {
	ApplicationID   int64
	ApplicationName string
}

func countEnabledListeners(listeners []model.ApplicationListener) int {
	count := 0
	for _, listener := range listeners {
		if listener.Enabled {
			count++
		}
	}
	return count
}

func countEnabledUpstreams(upstreams []model.ApplicationUpstream) int {
	count := 0
	for _, upstream := range upstreams {
		if upstream.Enabled {
			count++
		}
	}
	return count
}

type portRange struct {
	Start int
	End   int
}

func normalizeListenerDeployment(deployment GatewayListenerDeployment) (string, []portRange) {
	mode := strings.ToLower(strings.TrimSpace(deployment.Mode))
	if mode != "bridge-range" {
		mode = "host-network"
	}
	return mode, parsePortRanges(deployment.BridgePortRange)
}

func parsePortRanges(value string) []portRange {
	var ranges []portRange
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "-") {
			parts := strings.SplitN(item, "-", 2)
			start, errStart := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, errEnd := strconv.Atoi(strings.TrimSpace(parts[1]))
			if errStart != nil || errEnd != nil || start <= 0 || end > 65535 || start > end {
				continue
			}
			ranges = append(ranges, portRange{Start: start, End: end})
			continue
		}
		port, err := strconv.Atoi(item)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		ranges = append(ranges, portRange{Start: port, End: port})
	}
	return ranges
}

func portInRanges(port int, ranges []portRange) bool {
	for _, item := range ranges {
		if port >= item.Start && port <= item.End {
			return true
		}
	}
	return false
}

func rangeSummary(ranges []portRange) string {
	if len(ranges) == 0 {
		return "none"
	}
	out := make([]string, 0, len(ranges))
	for _, item := range ranges {
		if item.Start == item.End {
			out = append(out, strconv.Itoa(item.Start))
			continue
		}
		out = append(out, fmt.Sprintf("%d-%d", item.Start, item.End))
	}
	return strings.Join(out, ",")
}

func disabledReferenceIssues(applications map[int64]model.Application, policies []model.Policy, protectionRules []model.ProtectionRule, rateLimits []model.RateLimitRule, ipAccessLists []model.IPAccessListEntry, uploadRules []model.UploadProtectionRule, botRules []model.BotProtectionRule, dynamicRules []model.DynamicProtectionRule) []ApplicationValidationIssue {
	var issues []ApplicationValidationIssue
	add := func(source string, applicationID int64) {
		if applicationID <= 0 {
			return
		}
		app, ok := applications[applicationID]
		if !ok || app.Enabled {
			return
		}
		issues = append(issues, ApplicationValidationIssue{
			Severity:        "error",
			Category:        "disabled-application-reference",
			ApplicationID:   applicationID,
			ApplicationName: app.Name,
			Message:         fmt.Sprintf("%s references disabled application %d", source, applicationID),
		})
	}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		for _, applicationID := range policy.SiteIDs {
			add(fmt.Sprintf("policy %d", policy.ID), applicationID)
		}
	}
	for _, rule := range protectionRules {
		if rule.Enabled {
			add(fmt.Sprintf("protection rule %d", rule.ID), rule.SiteID)
		}
	}
	for _, rule := range rateLimits {
		if rule.Enabled {
			add(fmt.Sprintf("rate limit %d", rule.ID), rule.SiteID)
		}
	}
	for _, entry := range ipAccessLists {
		if entry.Enabled {
			add(fmt.Sprintf("ip access list %d", entry.ID), entry.SiteID)
		}
	}
	for _, rule := range uploadRules {
		if rule.Enabled {
			add(fmt.Sprintf("upload protection rule %d", rule.ID), rule.SiteID)
		}
	}
	for _, rule := range botRules {
		if rule.Enabled {
			add(fmt.Sprintf("bot protection rule %d", rule.ID), rule.SiteID)
		}
	}
	for _, rule := range dynamicRules {
		if rule.Enabled {
			add(fmt.Sprintf("dynamic protection rule %d", rule.ID), rule.SiteID)
		}
	}
	return issues
}

func applicationHostSet(hosts []model.ApplicationHost) map[string]bool {
	out := map[string]bool{}
	for _, host := range hosts {
		value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host.Host), "."))
		if value != "" {
			out[value] = true
		}
	}
	return out
}

func certificateCoversAnyHost(domains []string, hosts map[string]bool) bool {
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if domain == "" {
			continue
		}
		if hosts[domain] {
			return true
		}
		if strings.HasPrefix(domain, "*.") {
			suffix := strings.TrimPrefix(domain, "*.")
			for host := range hosts {
				if strings.HasSuffix(host, "."+suffix) && strings.Count(host, ".") == strings.Count(suffix, ".")+1 {
					return true
				}
			}
		}
	}
	return false
}

func Validate(ctx context.Context, dataStore store.Store) error {
	issues, err := ValidateApplicationReadiness(ctx, dataStore)
	if err != nil {
		return err
	}
	for _, issue := range issues {
		if issue.Severity == "error" {
			return fmt.Errorf("%s", issue.Message)
		}
	}

	applications, err := dataStore.ListApplications(ctx)
	if err != nil {
		return err
	}
	if len(applications) == 0 {
		sites, err := dataStore.ListSites(ctx)
		if err != nil {
			return err
		}
		applications = ApplicationsFromSites(sites)
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
	for _, application := range applications {
		if application.Enabled {
			siteIDs[application.ID] = true
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

func validatePublishedPathMatch(scope string, id int64, pathMatch string, rulePath string) error {
	if pathMatch == "" {
		pathMatch = protectionrules.PathMatchPrefix
	}
	if err := protectionrules.ValidatePathMatch(scope, pathMatch, rulePath); err != nil {
		return fmt.Errorf("%s rule %d %s", scope, id, strings.TrimPrefix(err.Error(), scope+" "))
	}
	return nil
}

func validateUploadProtectionRule(item model.UploadProtectionRule) error {
	if item.Name == "" {
		return fmt.Errorf("upload protection rule %d name is required", item.ID)
	}
	if err := validatePublishedPathMatch("upload protection", item.ID, item.PathMatch, item.Path); err != nil {
		return err
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
	if err := validatePublishedPathMatch("bot protection", item.ID, item.PathMatch, item.Path); err != nil {
		return err
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
	if err := validatePublishedPathMatch("dynamic protection", item.ID, item.PathMatch, item.Path); err != nil {
		return err
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

func WriteRuntimeArtifacts(ctx context.Context, dataStore store.Store, gatewayConfigPath string) (RuntimeArtifacts, error) {
	return WriteRuntimeArtifactsWithClientMaxBodySize(ctx, dataStore, gatewayConfigPath, gatewayconfig.DefaultClientMaxBodySize)
}

func WriteRuntimeArtifactsWithClientMaxBodySize(ctx context.Context, dataStore store.Store, gatewayConfigPath string, clientMaxBodySize string) (RuntimeArtifacts, error) {
	if err := Validate(ctx, dataStore); err != nil {
		return RuntimeArtifacts{}, err
	}
	applications, err := dataStore.ListApplications(ctx)
	if err != nil {
		return RuntimeArtifacts{}, err
	}
	if len(applications) == 0 {
		sites, err := dataStore.ListSites(ctx)
		if err != nil {
			return RuntimeArtifacts{}, err
		}
		applications = ApplicationsFromSites(sites)
	}
	return writeRuntimeArtifactsForApplications(ctx, dataStore, applications, gatewayConfigPath, clientMaxBodySize)
}

func WriteRuntimeArtifactsFromConfig(ctx context.Context, dataStore store.Store, configJSON []byte, gatewayConfigPath string) (RuntimeArtifacts, error) {
	return WriteRuntimeArtifactsFromConfigWithClientMaxBodySize(ctx, dataStore, configJSON, gatewayConfigPath, gatewayconfig.DefaultClientMaxBodySize)
}

func WriteRuntimeArtifactsFromConfigWithClientMaxBodySize(ctx context.Context, dataStore store.Store, configJSON []byte, gatewayConfigPath string, clientMaxBodySize string) (RuntimeArtifacts, error) {
	applications, err := ApplicationsFromConfigJSON(configJSON)
	if err != nil {
		return RuntimeArtifacts{}, err
	}
	return writeRuntimeArtifactsForApplications(ctx, dataStore, applications, gatewayConfigPath, clientMaxBodySize)
}

func ApplicationsFromConfigJSON(configJSON []byte) ([]model.Application, error) {
	var config ExtendedGatewayConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, err
	}
	applications := make([]model.Application, 0, len(config.Applications))
	for _, application := range config.Applications {
		applications = append(applications, model.Application{
			ID:          application.ID,
			Name:        application.Name,
			Mode:        application.Mode,
			Enabled:     application.Enabled,
			Hosts:       applicationHostsFromGateway(application.ID, application.Hosts),
			Listeners:   applicationListenersFromGateway(application.ID, application.Listeners),
			Upstreams:   applicationUpstreamsFromGateway(application.ID, application.Upstreams),
			ProxyConfig: cloneApplicationProxyConfig(application.ProxyConfig),
		})
	}
	return applications, nil
}

func cloneApplicationProxyConfig(input *model.ApplicationProxyConfig) *model.ApplicationProxyConfig {
	if input == nil {
		return nil
	}
	out := *input
	out.Headers = append([]model.ApplicationProxyHeader(nil), input.Headers...)
	return &out
}

func writeRuntimeArtifactsForApplications(ctx context.Context, dataStore store.Store, applications []model.Application, gatewayConfigPath string, clientMaxBodySize string) (RuntimeArtifacts, error) {
	artifacts, snapshot, _, err := buildRuntimeArtifactSnapshot(ctx, dataStore, applications, gatewayConfigPath, clientMaxBodySize, model.EmptyNginxConfigDraft(), model.NginxValidationResult{})
	if err != nil {
		return RuntimeArtifacts{}, err
	}
	if err := WriteRuntimeArtifactSnapshot(snapshot); err != nil {
		return RuntimeArtifacts{}, err
	}
	artifacts.RuntimeArtifactJSON = encodeRuntimeArtifactSnapshot(snapshot)
	return artifacts, nil
}

func WriteRuntimeArtifactsWithAdvancedNginx(ctx context.Context, dataStore store.Store, gatewayConfigPath string, clientMaxBodySize string, validationCommand string) (RuntimeArtifacts, error) {
	applications, err := dataStore.ListApplications(ctx)
	if err != nil {
		return RuntimeArtifacts{}, err
	}
	if len(applications) == 0 {
		sites, err := dataStore.ListSites(ctx)
		if err != nil {
			return RuntimeArtifacts{}, err
		}
		applications = ApplicationsFromSites(sites)
	}
	draft, err := dataStore.GetNginxConfigDraft(ctx)
	if err != nil {
		return RuntimeArtifacts{}, err
	}
	review, snapshot, artifacts, err := buildAdvancedNginxReview(ctx, dataStore, applications, gatewayConfigPath, clientMaxBodySize, validationCommand, draft)
	if err != nil {
		return RuntimeArtifacts{}, err
	}
	if review.HasAdvancedChanges && review.Validation.Status != model.NginxValidationStatusPassed {
		return RuntimeArtifacts{}, fmt.Errorf("advanced nginx config validation %s: %s", review.Validation.Status, review.Validation.Message)
	}
	if err := WriteRuntimeArtifactSnapshot(snapshot); err != nil {
		return RuntimeArtifacts{}, err
	}
	artifacts.Validation = review.Validation
	artifacts.RuntimeArtifactJSON = encodeRuntimeArtifactSnapshot(snapshot)
	return artifacts, nil
}

func BuildAdvancedNginxReview(ctx context.Context, dataStore store.Store, gatewayConfigPath string, clientMaxBodySize string, validationCommand string) (AdvancedNginxReview, error) {
	applications, err := dataStore.ListApplications(ctx)
	if err != nil {
		return AdvancedNginxReview{}, err
	}
	if len(applications) == 0 {
		sites, err := dataStore.ListSites(ctx)
		if err != nil {
			return AdvancedNginxReview{}, err
		}
		applications = ApplicationsFromSites(sites)
	}
	draft, err := dataStore.GetNginxConfigDraft(ctx)
	if err != nil {
		return AdvancedNginxReview{}, err
	}
	review, _, _, err := buildAdvancedNginxReview(ctx, dataStore, applications, gatewayConfigPath, clientMaxBodySize, validationCommand, draft)
	return review, err
}

func buildAdvancedNginxReview(ctx context.Context, dataStore store.Store, applications []model.Application, gatewayConfigPath string, clientMaxBodySize string, validationCommand string, draft model.NginxConfigDraft) (AdvancedNginxReview, RuntimeArtifactSnapshot, RuntimeArtifacts, error) {
	hasAdvanced := model.NginxConfigDraftHasAdvancedChanges(draft)
	review := AdvancedNginxReview{
		HasAdvancedChanges: hasAdvanced,
		Mode:               draft.Mode,
		Warnings:           advancedNginxWarnings(draft),
		Validation:         model.NginxValidationResult{Status: model.NginxValidationStatusUnchecked},
	}
	if draft.Mode == model.NginxConfigModeFull && strings.TrimSpace(draft.FullConfig) != "" {
		if issues := ValidateFullNginxConfigInvariants(draft.FullConfig); len(issues) > 0 {
			review.Validation = model.NginxValidationResult{
				Status:      model.NginxValidationStatusFailed,
				Message:     "full nginx.conf override is missing LiteWaf invariants",
				Diagnostics: issues,
				ValidatedAt: time.Now().UTC().Format(time.RFC3339),
			}
			artifacts, snapshot, _, err := buildRuntimeArtifactSnapshot(ctx, dataStore, applications, gatewayConfigPath, clientMaxBodySize, draft, review.Validation)
			if err != nil {
				return review, RuntimeArtifactSnapshot{}, RuntimeArtifacts{}, err
			}
			review.Diff = buildRuntimeDiff(snapshot)
			return review, snapshot, artifacts, nil
		}
	}
	validation := model.NginxValidationResult{Status: model.NginxValidationStatusUnchecked}
	artifacts, snapshot, effectiveConfigPath, err := buildRuntimeArtifactSnapshot(ctx, dataStore, applications, gatewayConfigPath, clientMaxBodySize, draft, validation)
	if err != nil {
		return review, RuntimeArtifactSnapshot{}, RuntimeArtifacts{}, err
	}
	if hasAdvanced {
		validation = ValidateEffectiveNginxConfig(ctx, validationCommand, snapshotWithEffectiveConfig(snapshot, effectiveConfigPath, effectiveNginxConfig(snapshot, effectiveConfigPath)), effectiveConfigPath)
		artifacts.Validation = validation
		review.Validation = validation
	} else {
		review.Validation = validation
	}
	if hasAdvanced {
		review.Diff = buildRuntimeDiff(snapshot)
	}
	return review, snapshot, artifacts, nil
}

func buildRuntimeArtifactSnapshot(ctx context.Context, dataStore store.Store, applications []model.Application, gatewayConfigPath string, clientMaxBodySize string, draft model.NginxConfigDraft, validation model.NginxValidationResult) (RuntimeArtifacts, RuntimeArtifactSnapshot, string, error) {
	normalizedClientMaxBodySize, err := gatewayconfig.NormalizeClientMaxBodySize(clientMaxBodySize)
	if err != nil {
		return RuntimeArtifacts{}, RuntimeArtifactSnapshot{}, "", err
	}
	certificates, err := dataStore.ListCertificates(ctx)
	if err != nil {
		return RuntimeArtifacts{}, RuntimeArtifactSnapshot{}, "", err
	}
	certificateByID := map[int64]model.Certificate{}
	for _, cert := range certificates {
		certificateByID[cert.ID] = cert
	}

	baseDir := filepath.Dir(gatewayConfigPath)
	listenerDir := filepath.Join(baseDir, "listeners")
	certificateDir := filepath.Join(baseDir, "certificates")
	snippetDir := filepath.Join(listenerDir, "snippets")

	usedCertificates := map[int64]bool{}
	snippets := snippetsByPoint(draft)
	listenerConfig, listenerCount, httpsCount := buildListenerConfigWithSnippets(applications, "/etc/litewaf/certificates", usedCertificates, snippets)
	listenerConfigPath := filepath.Join(listenerDir, "applications.conf")
	bodySizeConfigPath := filepath.Join(listenerDir, "body-size.conf")
	snapshot := RuntimeArtifactSnapshot{Files: []RuntimeArtifactFile{
		{Path: listenerConfigPath, Content: listenerConfig, Mode: 0o644},
		{Path: bodySizeConfigPath, Content: buildBodySizeConfig(normalizedClientMaxBodySize), Mode: 0o644},
	}}
	for _, point := range []string{model.NginxSnippetPointHTTP, model.NginxSnippetPointServer, model.NginxSnippetPointLocation} {
		content := strings.TrimSpace(snippets[point])
		if content == "" {
			continue
		}
		snapshot.Files = append(snapshot.Files, RuntimeArtifactFile{
			Path:    filepath.Join(snippetDir, point+".conf"),
			Content: "# generated from LiteWaf advanced nginx snippet draft\n" + content + "\n",
			Mode:    0o644,
		})
	}
	certificateIDs := make([]int64, 0, len(usedCertificates))
	for id := range usedCertificates {
		cert, ok := certificateByID[id]
		if !ok {
			return RuntimeArtifacts{}, RuntimeArtifactSnapshot{}, "", fmt.Errorf("certificate %d does not exist", id)
		}
		crtPath := filepath.Join(certificateDir, fmt.Sprintf("%d.crt", id))
		keyPath := filepath.Join(certificateDir, fmt.Sprintf("%d.key", id))
		snapshot.Files = append(snapshot.Files,
			RuntimeArtifactFile{Path: crtPath, Content: cert.CertPEM + "\n", Mode: 0o644},
			RuntimeArtifactFile{Path: keyPath, Content: cert.KeyPEM + "\n", Mode: 0o600},
		)
		certificateIDs = append(certificateIDs, id)
	}
	sort.Slice(certificateIDs, func(i, j int) bool { return certificateIDs[i] < certificateIDs[j] })
	nginxConfigPath := filepath.Join(baseDir, "nginx.conf")
	effectiveConfig := buildDefaultNginxConfig(listenerDir)
	fullOverrideActive := draft.Mode == model.NginxConfigModeFull && strings.TrimSpace(draft.FullConfig) != ""
	if fullOverrideActive {
		effectiveConfig = strings.TrimSpace(draft.FullConfig) + "\n"
		snapshot.Files = append(snapshot.Files, RuntimeArtifactFile{Path: nginxConfigPath, Content: effectiveConfig, Mode: 0o644})
	}
	return RuntimeArtifacts{
		ListenerConfigPath: listenerConfigPath,
		BodySizeConfigPath: bodySizeConfigPath,
		SnippetConfigDir:   snippetDir,
		NginxConfigPath:    nginxConfigPath,
		ClientMaxBodySize:  normalizedClientMaxBodySize,
		CertificateDir:     certificateDir,
		ListenerCount:      listenerCount,
		HTTPSListenerCount: httpsCount,
		CertificateIDs:     certificateIDs,
		AdvancedConfig:     model.NginxConfigDraftHasAdvancedChanges(draft),
		FullOverrideActive: fullOverrideActive,
		Validation:         validation,
	}, snapshot, nginxConfigPath, nil
}

func buildBodySizeConfig(clientMaxBodySize string) string {
	return fmt.Sprintf("# generated by litewaf publish; do not edit\nclient_max_body_size %s;\n", clientMaxBodySize)
}

func WriteRuntimeArtifactSnapshot(snapshot RuntimeArtifactSnapshot) error {
	for _, file := range snapshot.Files {
		if strings.TrimSpace(file.Path) == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(file.Path), 0o755); err != nil {
			return err
		}
		if err := WriteAtomic(file.Path, []byte(file.Content)); err != nil {
			return err
		}
		if file.Mode != 0 {
			if err := os.Chmod(file.Path, os.FileMode(file.Mode)); err != nil {
				return err
			}
		}
	}
	return nil
}

func RuntimeArtifactSnapshotFromJSON(value string) (RuntimeArtifactSnapshot, error) {
	var snapshot RuntimeArtifactSnapshot
	if strings.TrimSpace(value) == "" {
		return snapshot, nil
	}
	if err := json.Unmarshal([]byte(value), &snapshot); err != nil {
		return RuntimeArtifactSnapshot{}, err
	}
	return snapshot, nil
}

func RuntimeArtifactsFromSnapshot(snapshot RuntimeArtifactSnapshot, gatewayConfigPath string, clientMaxBodySize string, applications []model.Application) RuntimeArtifacts {
	bodySize, err := gatewayconfig.NormalizeClientMaxBodySize(clientMaxBodySize)
	if err != nil {
		bodySize = gatewayconfig.DefaultClientMaxBodySize
	}
	baseDir := filepath.Dir(gatewayConfigPath)
	listenerDir := filepath.Join(baseDir, "listeners")
	certificateDir := filepath.Join(baseDir, "certificates")
	certificateIDs := []int64{}
	certificateSeen := map[int64]bool{}
	listenerCount := 0
	httpsCount := 0
	for _, app := range applications {
		if !app.Enabled {
			continue
		}
		for _, listener := range app.Listeners {
			if !listener.Enabled {
				continue
			}
			listenerCount++
			if listener.Protocol == model.ListenerProtocolHTTPS {
				httpsCount++
				if listener.CertificateID > 0 && !certificateSeen[listener.CertificateID] {
					certificateIDs = append(certificateIDs, listener.CertificateID)
					certificateSeen[listener.CertificateID] = true
				}
			}
		}
	}
	sort.Slice(certificateIDs, func(i, j int) bool { return certificateIDs[i] < certificateIDs[j] })
	fullOverride := false
	for _, file := range snapshot.Files {
		if filepath.Clean(file.Path) == filepath.Clean(filepath.Join(baseDir, "nginx.conf")) {
			fullOverride = true
			break
		}
	}
	return RuntimeArtifacts{
		ListenerConfigPath:  filepath.Join(listenerDir, "applications.conf"),
		BodySizeConfigPath:  filepath.Join(listenerDir, "body-size.conf"),
		SnippetConfigDir:    filepath.Join(listenerDir, "snippets"),
		NginxConfigPath:     filepath.Join(baseDir, "nginx.conf"),
		ClientMaxBodySize:   bodySize,
		CertificateDir:      certificateDir,
		ListenerCount:       listenerCount,
		HTTPSListenerCount:  httpsCount,
		CertificateIDs:      certificateIDs,
		AdvancedConfig:      fullOverride,
		FullOverrideActive:  fullOverride,
		RuntimeArtifactJSON: encodeRuntimeArtifactSnapshot(snapshot),
	}
}

func encodeRuntimeArtifactSnapshot(snapshot RuntimeArtifactSnapshot) string {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return ""
	}
	return string(payload)
}

func snapshotWithEffectiveConfig(snapshot RuntimeArtifactSnapshot, nginxConfigPath string, effectiveConfig string) RuntimeArtifactSnapshot {
	for i := range snapshot.Files {
		if filepath.Clean(snapshot.Files[i].Path) == filepath.Clean(nginxConfigPath) {
			snapshot.Files[i].Content = effectiveConfig
			return snapshot
		}
	}
	snapshot.Files = append(snapshot.Files, RuntimeArtifactFile{Path: nginxConfigPath, Content: effectiveConfig, Mode: 0o644})
	return snapshot
}

func effectiveNginxConfig(snapshot RuntimeArtifactSnapshot, nginxConfigPath string) string {
	for _, file := range snapshot.Files {
		if filepath.Clean(file.Path) == filepath.Clean(nginxConfigPath) {
			return file.Content
		}
	}
	return buildDefaultNginxConfig(filepath.Join(filepath.Dir(nginxConfigPath), "listeners"))
}

func ValidateEffectiveNginxConfig(ctx context.Context, command string, snapshot RuntimeArtifactSnapshot, configPath string) model.NginxValidationResult {
	command = strings.TrimSpace(command)
	now := time.Now().UTC().Format(time.RFC3339)
	if command == "" {
		return model.NginxValidationResult{
			Status:      model.NginxValidationStatusUnavailable,
			Message:     "nginx validation command is not configured",
			ValidatedAt: now,
		}
	}
	stageDir, err := os.MkdirTemp("", "litewaf-nginx-validate-*")
	if err != nil {
		return model.NginxValidationResult{Status: model.NginxValidationStatusUnavailable, Message: err.Error(), ValidatedAt: now}
	}
	defer os.RemoveAll(stageDir)
	baseDir := filepath.Dir(configPath)
	stageSnapshot := RuntimeArtifactSnapshot{Files: make([]RuntimeArtifactFile, 0, len(snapshot.Files))}
	for _, file := range snapshot.Files {
		rel, err := filepath.Rel(baseDir, file.Path)
		if err != nil || strings.HasPrefix(rel, "..") {
			rel = filepath.Base(file.Path)
		}
		stagePath := filepath.Join(stageDir, rel)
		content := strings.ReplaceAll(file.Content, filepath.ToSlash(baseDir), filepath.ToSlash(stageDir))
		content = strings.ReplaceAll(content, baseDir, stageDir)
		stageSnapshot.Files = append(stageSnapshot.Files, RuntimeArtifactFile{Path: stagePath, Content: content, Mode: file.Mode})
	}
	if err := WriteRuntimeArtifactSnapshot(stageSnapshot); err != nil {
		return model.NginxValidationResult{Status: model.NginxValidationStatusUnavailable, Message: err.Error(), ValidatedAt: now}
	}
	stageConfigPath := filepath.Join(stageDir, filepath.Base(configPath))
	renderedCommand := strings.ReplaceAll(command, "{config}", shellQuote(stageConfigPath))
	renderedCommand = strings.ReplaceAll(renderedCommand, "{prefix}", shellQuote(stageDir))
	cmd := shellCommand(ctx, renderedCommand)
	output, err := cmd.CombinedOutput()
	message := boundedValidationMessage(string(output))
	if err != nil {
		if message == "" {
			message = err.Error()
		}
		return model.NginxValidationResult{
			Status:      model.NginxValidationStatusFailed,
			Command:     renderedCommand,
			Message:     message,
			Diagnostics: splitValidationDiagnostics(message),
			ValidatedAt: now,
		}
	}
	if message == "" {
		message = "nginx config validation passed"
	}
	return model.NginxValidationResult{
		Status:      model.NginxValidationStatusPassed,
		Command:     renderedCommand,
		Message:     message,
		Diagnostics: splitValidationDiagnostics(message),
		ValidatedAt: now,
	}
}

func shellCommand(ctx context.Context, command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd", "/C", command)
	}
	return exec.CommandContext(ctx, "sh", "-c", command)
}

func shellQuote(value string) string {
	if runtime.GOOS == "windows" {
		return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func boundedValidationMessage(message string) string {
	message = strings.TrimSpace(message)
	const maxLen = 4000
	if len(message) > maxLen {
		return message[:maxLen]
	}
	return message
}

func splitValidationDiagnostics(message string) []string {
	lines := strings.Split(strings.ReplaceAll(message, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func buildRuntimeDiff(snapshot RuntimeArtifactSnapshot) string {
	var builder strings.Builder
	for _, file := range snapshot.Files {
		if isSensitiveRuntimeArtifact(file.Path) {
			continue
		}
		current, err := os.ReadFile(file.Path)
		if err == nil && string(current) == file.Content {
			continue
		}
		builder.WriteString("--- ")
		builder.WriteString(file.Path)
		builder.WriteString("\n+++ staged\n")
		if err == nil && len(current) > 0 {
			builder.WriteString("@@ current @@\n")
			builder.WriteString(limitDiffContent(string(current)))
			if !strings.HasSuffix(builder.String(), "\n") {
				builder.WriteString("\n")
			}
		}
		builder.WriteString("@@ staged @@\n")
		builder.WriteString(limitDiffContent(file.Content))
		if !strings.HasSuffix(builder.String(), "\n") {
			builder.WriteString("\n")
		}
	}
	return builder.String()
}

func isSensitiveRuntimeArtifact(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".key" || ext == ".crt" || ext == ".pem"
}

func limitDiffContent(value string) string {
	const maxLen = 6000
	if len(value) > maxLen {
		return value[:maxLen] + "\n... truncated ..."
	}
	return value
}

func advancedNginxWarnings(draft model.NginxConfigDraft) []string {
	if !model.NginxConfigDraftHasAdvancedChanges(draft) {
		return []string{}
	}
	warnings := []string{
		"Advanced nginx changes can stop the gateway or bypass LiteWaf request handling if published incorrectly.",
		"Publishing requires effective nginx validation and explicit confirmation.",
	}
	if draft.Mode == model.NginxConfigModeFull && strings.TrimSpace(draft.FullConfig) != "" {
		warnings = append(warnings, "Full nginx.conf override is the highest-risk mode and must preserve LiteWaf Lua hooks, health checks, listener includes, and proxy execution.")
	}
	return warnings
}

func ValidateFullNginxConfigInvariants(config string) []string {
	required := map[string]string{
		"health endpoint":           "location = /healthz",
		"metrics endpoint":          "litewaf.metrics()",
		"LiteWaf module loading":    `require "litewaf"`,
		"LiteWaf worker init":       "litewaf.init_worker()",
		"LiteWaf access hook":       "litewaf.access()",
		"LiteWaf header hook":       "litewaf.header_filter()",
		"LiteWaf body hook":         "litewaf.body_filter()",
		"LiteWaf log hook":          "litewaf.log()",
		"runtime listener include":  "/etc/litewaf/listeners/*.conf",
		"selected upstream proxy":   "proxy_pass $litewaf_upstream",
		"runtime upstream variable": "$litewaf_upstream",
	}
	issues := []string{}
	for label, needle := range required {
		if !strings.Contains(config, needle) {
			issues = append(issues, fmt.Sprintf("missing %s (%s)", label, needle))
		}
	}
	sort.Strings(issues)
	return issues
}

func snippetsByPoint(draft model.NginxConfigDraft) map[string]string {
	out := map[string]string{}
	if draft.Mode != model.NginxConfigModeSnippets {
		return out
	}
	for _, snippet := range draft.Snippets {
		content := strings.TrimSpace(snippet.Content)
		if content == "" {
			continue
		}
		out[snippet.IncludePoint] = strings.TrimSpace(out[snippet.IncludePoint] + "\n" + content)
	}
	return out
}

func buildDefaultNginxConfig(listenerDir string) string {
	listenerInclude := filepath.ToSlash(filepath.Join(listenerDir, "*.conf"))
	return fmt.Sprintf(`worker_processes auto;
error_log /dev/stderr warn;

events {
    worker_connections 1024;
}

http {
    lua_package_path "/usr/local/openresty/nginx/lua/?.lua;;";
    lua_shared_dict litewaf_rate_limit 10m;
    lua_shared_dict litewaf_dynamic_ban 10m;
    lua_shared_dict litewaf_dynamic_ban_clear 1m;
    lua_shared_dict litewaf_dynamic_protection 10m;
    lua_shared_dict litewaf_metrics 10m;
    include /usr/local/openresty/nginx/conf/litewaf-realip.conf;
    include %s;

    resolver 127.0.0.11 ipv6=off valid=10s;

    init_by_lua_block {
        litewaf = require "litewaf"
    }

    init_worker_by_lua_block {
        litewaf.init_worker()
    }
}
`, listenerInclude)
}

func DefaultNginxConfig(listenerDir string) string {
	return buildDefaultNginxConfig(listenerDir)
}

func applicationHostsFromGateway(applicationID int64, hosts []string) []model.ApplicationHost {
	out := make([]model.ApplicationHost, 0, len(hosts))
	for i, host := range hosts {
		out = append(out, model.ApplicationHost{
			ApplicationID: applicationID,
			Host:          host,
			IsPrimary:     i == 0,
		})
	}
	return out
}

func applicationListenersFromGateway(applicationID int64, listeners []GatewayApplicationListener) []model.ApplicationListener {
	out := make([]model.ApplicationListener, 0, len(listeners))
	for _, listener := range listeners {
		out = append(out, model.ApplicationListener{
			ApplicationID: applicationID,
			Port:          listener.Port,
			Protocol:      listener.Protocol,
			CertificateID: listener.CertificateID,
			Enabled:       listener.Enabled,
		})
	}
	return out
}

func applicationUpstreamsFromGateway(applicationID int64, upstreams []GatewayApplicationUpstream) []model.ApplicationUpstream {
	out := make([]model.ApplicationUpstream, 0, len(upstreams))
	for _, upstream := range upstreams {
		out = append(out, model.ApplicationUpstream{
			ApplicationID: applicationID,
			Name:          upstream.Name,
			URL:           upstream.URL,
			Weight:        upstream.Weight,
			Enabled:       upstream.Enabled,
		})
	}
	return out
}

func buildListenerConfig(applications []model.Application, certificateDir string, usedCertificates map[int64]bool) (string, int, int) {
	return buildListenerConfigWithSnippets(applications, certificateDir, usedCertificates, map[string]string{})
}

func buildListenerConfigWithSnippets(applications []model.Application, certificateDir string, usedCertificates map[int64]bool, snippets map[string]string) (string, int, int) {
	var builder strings.Builder
	builder.WriteString("# generated by litewaf publish; do not edit\n")
	if content := strings.TrimSpace(snippets[model.NginxSnippetPointHTTP]); content != "" {
		builder.WriteString("\n# LiteWaf controlled http snippet\n")
		builder.WriteString(content)
		builder.WriteString("\n")
	}
	listenerCount := 0
	httpsCount := 0
	for _, application := range applications {
		if !application.Enabled {
			continue
		}
		for _, listener := range application.Listeners {
			if !listener.Enabled {
				continue
			}
			listenerCount++
			if listener.Protocol == model.ListenerProtocolHTTPS {
				httpsCount++
				usedCertificates[listener.CertificateID] = true
			}
			writeListenerServer(&builder, application, listener, certificateDir, snippets)
		}
	}
	return builder.String(), listenerCount, httpsCount
}

func writeListenerServer(builder *strings.Builder, application model.Application, listener model.ApplicationListener, certificateDir string, snippets map[string]string) {
	listenSuffix := ""
	if listener.Protocol == model.ListenerProtocolHTTPS {
		listenSuffix = " ssl"
	}
	builder.WriteString("\nserver {\n")
	builder.WriteString(fmt.Sprintf("    listen %d%s;\n", listener.Port, listenSuffix))
	builder.WriteString(fmt.Sprintf("    server_name %s;\n", nginxServerNames(application.Hosts)))
	if listener.Protocol == model.ListenerProtocolHTTPS {
		certPrefix := strings.ReplaceAll(filepath.ToSlash(filepath.Join(certificateDir, fmt.Sprintf("%d", listener.CertificateID))), "\\", "/")
		builder.WriteString(fmt.Sprintf("    ssl_certificate %s.crt;\n", certPrefix))
		builder.WriteString(fmt.Sprintf("    ssl_certificate_key %s.key;\n", certPrefix))
		builder.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
	}
	builder.WriteString("\n")
	builder.WriteString("    location = /healthz {\n")
	builder.WriteString("        default_type application/json;\n")
	builder.WriteString("        return 200 '{\"status\":\"ok\"}';\n")
	builder.WriteString("    }\n\n")
	builder.WriteString("    location = /metrics {\n")
	builder.WriteString("        content_by_lua_block { litewaf.metrics() }\n")
	builder.WriteString("    }\n\n")
	if content := strings.TrimSpace(snippets[model.NginxSnippetPointServer]); content != "" {
		builder.WriteString("    # LiteWaf controlled server snippet\n")
		writeIndentedSnippet(builder, content, "    ")
		builder.WriteString("\n")
	}
	builder.WriteString("    location / {\n")
	builder.WriteString("        set $litewaf_upstream \"\";\n")
	builder.WriteString("        set $litewaf_request_id \"\";\n")
	builder.WriteString("        set $litewaf_client_ip $remote_addr;\n\n")
	builder.WriteString("        access_by_lua_block { litewaf.access() }\n")
	builder.WriteString("        header_filter_by_lua_block { litewaf.header_filter() }\n")
	builder.WriteString("        body_filter_by_lua_block { litewaf.body_filter() }\n")
	builder.WriteString("        log_by_lua_block { litewaf.log() }\n\n")
	builder.WriteString("        proxy_http_version 1.1;\n")
	writeApplicationProxyDirectives(builder, application.ProxyConfig)
	if content := strings.TrimSpace(snippets[model.NginxSnippetPointLocation]); content != "" {
		builder.WriteString("\n        # LiteWaf controlled location snippet\n")
		writeIndentedSnippet(builder, content, "        ")
	}
	builder.WriteString("        proxy_pass $litewaf_upstream;\n")
	builder.WriteString("    }\n")
	builder.WriteString("}\n")
}

func writeApplicationProxyDirectives(builder *strings.Builder, config *model.ApplicationProxyConfig) {
	preserveHost := true
	if config != nil && config.PreserveHost != nil {
		preserveHost = *config.PreserveHost
	}
	if preserveHost {
		builder.WriteString("        proxy_set_header Host $host;\n")
	} else {
		builder.WriteString("        proxy_set_header Host $proxy_host;\n")
	}
	builder.WriteString("        proxy_set_header X-Real-IP $litewaf_client_ip;\n")
	builder.WriteString("        proxy_set_header X-Request-ID $litewaf_request_id;\n")
	builder.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	builder.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	if config == nil {
		return
	}
	if config.WebSocketEnabled {
		builder.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		builder.WriteString("        proxy_set_header Connection \"upgrade\";\n")
	}
	if config.ConnectTimeout != "" {
		builder.WriteString(fmt.Sprintf("        proxy_connect_timeout %s;\n", config.ConnectTimeout))
	}
	if config.ReadTimeout != "" {
		builder.WriteString(fmt.Sprintf("        proxy_read_timeout %s;\n", config.ReadTimeout))
	}
	if config.SendTimeout != "" {
		builder.WriteString(fmt.Sprintf("        proxy_send_timeout %s;\n", config.SendTimeout))
	}
	if config.ProxyBuffering != "" {
		builder.WriteString(fmt.Sprintf("        proxy_buffering %s;\n", config.ProxyBuffering))
	}
	if config.RequestBuffering != "" {
		builder.WriteString(fmt.Sprintf("        proxy_request_buffering %s;\n", config.RequestBuffering))
	}
	for _, header := range config.Headers {
		builder.WriteString(fmt.Sprintf("        proxy_set_header %s %s;\n", header.Name, escapeNginxHeaderValue(header.Value)))
	}
}

func escapeNginxHeaderValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return `""`
	}
	if strings.HasPrefix(value, "$") && !strings.ContainsAny(value, " ;{}") {
		return value
	}
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func writeIndentedSnippet(builder *strings.Builder, content string, indent string) {
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			builder.WriteString("\n")
			continue
		}
		builder.WriteString(indent)
		builder.WriteString(line)
		builder.WriteString("\n")
	}
}

func nginxServerNames(hosts []model.ApplicationHost) string {
	names := make([]string, 0, len(hosts))
	for _, host := range hosts {
		value := strings.TrimSpace(host.Host)
		if value == "" {
			continue
		}
		names = append(names, value)
	}
	if len(names) == 0 {
		return "_"
	}
	return strings.Join(names, " ")
}
