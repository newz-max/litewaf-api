package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"litewaf-api/internal/attackmeta"
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
	ID        int64                        `json:"id"`
	Name      string                       `json:"name"`
	Mode      string                       `json:"mode"`
	Enabled   bool                         `json:"enabled"`
	Hosts     []string                     `json:"hosts"`
	Listeners []GatewayApplicationListener `json:"listeners"`
	Upstreams []GatewayApplicationUpstream `json:"upstreams"`
	Rules     []GatewayRule                `json:"rules"`
	Policy    GatewayPolicy                `json:"policy"`
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
	ListenerConfigPath string  `json:"listener_config_path"`
	CertificateDir     string  `json:"certificate_dir"`
	ListenerCount      int     `json:"listener_count"`
	HTTPSListenerCount int     `json:"https_listener_count"`
	CertificateIDs     []int64 `json:"certificate_ids"`
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
			ID:        application.ID,
			Name:      application.Name,
			Mode:      application.Mode,
			Enabled:   application.Enabled,
			Hosts:     gatewayHosts(application.Hosts),
			Listeners: gatewayListeners(application.Listeners),
			Upstreams: gatewayUpstreams(application.Upstreams),
			Rules:     []GatewayRule{},
			Policy:    gatewayPolicy(sitePolicies[application.ID]),
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
	return writeRuntimeArtifactsForApplications(ctx, dataStore, applications, gatewayConfigPath)
}

func WriteRuntimeArtifactsFromConfig(ctx context.Context, dataStore store.Store, configJSON []byte, gatewayConfigPath string) (RuntimeArtifacts, error) {
	applications, err := ApplicationsFromConfigJSON(configJSON)
	if err != nil {
		return RuntimeArtifacts{}, err
	}
	return writeRuntimeArtifactsForApplications(ctx, dataStore, applications, gatewayConfigPath)
}

func ApplicationsFromConfigJSON(configJSON []byte) ([]model.Application, error) {
	var config ExtendedGatewayConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, err
	}
	applications := make([]model.Application, 0, len(config.Applications))
	for _, application := range config.Applications {
		applications = append(applications, model.Application{
			ID:        application.ID,
			Name:      application.Name,
			Mode:      application.Mode,
			Enabled:   application.Enabled,
			Hosts:     applicationHostsFromGateway(application.ID, application.Hosts),
			Listeners: applicationListenersFromGateway(application.ID, application.Listeners),
			Upstreams: applicationUpstreamsFromGateway(application.ID, application.Upstreams),
		})
	}
	return applications, nil
}

func writeRuntimeArtifactsForApplications(ctx context.Context, dataStore store.Store, applications []model.Application, gatewayConfigPath string) (RuntimeArtifacts, error) {
	certificates, err := dataStore.ListCertificates(ctx)
	if err != nil {
		return RuntimeArtifacts{}, err
	}
	certificateByID := map[int64]model.Certificate{}
	for _, cert := range certificates {
		certificateByID[cert.ID] = cert
	}

	baseDir := filepath.Dir(gatewayConfigPath)
	listenerDir := filepath.Join(baseDir, "listeners")
	certificateDir := filepath.Join(baseDir, "certificates")
	if err := os.MkdirAll(listenerDir, 0o755); err != nil {
		return RuntimeArtifacts{}, err
	}
	if err := os.MkdirAll(certificateDir, 0o700); err != nil {
		return RuntimeArtifacts{}, err
	}

	usedCertificates := map[int64]bool{}
	listenerConfig, listenerCount, httpsCount := buildListenerConfig(applications, "/etc/litewaf/certificates", usedCertificates)
	listenerConfigPath := filepath.Join(listenerDir, "applications.conf")
	if err := WriteAtomic(listenerConfigPath, []byte(listenerConfig)); err != nil {
		return RuntimeArtifacts{}, err
	}
	certificateIDs := make([]int64, 0, len(usedCertificates))
	for id := range usedCertificates {
		cert, ok := certificateByID[id]
		if !ok {
			return RuntimeArtifacts{}, fmt.Errorf("certificate %d does not exist", id)
		}
		crtPath := filepath.Join(certificateDir, fmt.Sprintf("%d.crt", id))
		keyPath := filepath.Join(certificateDir, fmt.Sprintf("%d.key", id))
		if err := WriteAtomic(crtPath, []byte(cert.CertPEM+"\n")); err != nil {
			return RuntimeArtifacts{}, err
		}
		if err := WriteAtomic(keyPath, []byte(cert.KeyPEM+"\n")); err != nil {
			return RuntimeArtifacts{}, err
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			return RuntimeArtifacts{}, err
		}
		certificateIDs = append(certificateIDs, id)
	}
	sort.Slice(certificateIDs, func(i, j int) bool { return certificateIDs[i] < certificateIDs[j] })
	return RuntimeArtifacts{
		ListenerConfigPath: listenerConfigPath,
		CertificateDir:     certificateDir,
		ListenerCount:      listenerCount,
		HTTPSListenerCount: httpsCount,
		CertificateIDs:     certificateIDs,
	}, nil
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
	var builder strings.Builder
	builder.WriteString("# generated by litewaf publish; do not edit\n")
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
			writeListenerServer(&builder, application, listener, certificateDir)
		}
	}
	return builder.String(), listenerCount, httpsCount
}

func writeListenerServer(builder *strings.Builder, application model.Application, listener model.ApplicationListener, certificateDir string) {
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
	builder.WriteString("    location / {\n")
	builder.WriteString("        set $litewaf_upstream \"\";\n")
	builder.WriteString("        set $litewaf_request_id \"\";\n")
	builder.WriteString("        set $litewaf_client_ip $remote_addr;\n\n")
	builder.WriteString("        access_by_lua_block { litewaf.access() }\n")
	builder.WriteString("        header_filter_by_lua_block { litewaf.header_filter() }\n")
	builder.WriteString("        body_filter_by_lua_block { litewaf.body_filter() }\n")
	builder.WriteString("        log_by_lua_block { litewaf.log() }\n\n")
	builder.WriteString("        proxy_http_version 1.1;\n")
	builder.WriteString("        proxy_set_header Host $host;\n")
	builder.WriteString("        proxy_set_header X-Real-IP $litewaf_client_ip;\n")
	builder.WriteString("        proxy_set_header X-Request-ID $litewaf_request_id;\n")
	builder.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	builder.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	builder.WriteString("        proxy_pass $litewaf_upstream;\n")
	builder.WriteString("    }\n")
	builder.WriteString("}\n")
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
