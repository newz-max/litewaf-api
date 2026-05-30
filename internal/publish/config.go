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
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Scope       string `json:"scope"`
	MatchValue  string `json:"match_value"`
	Threshold   int    `json:"threshold"`
	WindowSec   int    `json:"window_sec"`
	Action      string `json:"action"`
	BanDuration int    `json:"ban_duration_sec"`
	SiteID      int64  `json:"site_id"`
}

type ExtendedGatewayConfig struct {
	Version     string                   `json:"version"`
	GeneratedAt time.Time                `json:"generated_at"`
	Sites       []GatewaySite            `json:"sites"`
	AccessLists []GatewayAccessListEntry `json:"access_lists"`
	RateLimits  []GatewayRateLimitRule   `json:"rate_limits"`
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
		}
	}

	config := ExtendedGatewayConfig{
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Sites:       []GatewaySite{},
		AccessLists: []GatewayAccessListEntry{},
		RateLimits:  []GatewayRateLimitRule{},
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
			ID:          item.ID,
			Name:        item.Name,
			Scope:       item.Scope,
			MatchValue:  item.MatchValue,
			Threshold:   item.Threshold,
			WindowSec:   item.WindowSec,
			Action:      item.Action,
			BanDuration: item.BanDuration,
			SiteID:      item.SiteID,
		})
	}

	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return ExtendedGatewayConfig{}, nil, "", err
	}
	sum := sha256.Sum256(payload)
	return config, payload, hex.EncodeToString(sum[:]), nil
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
			return fmt.Errorf("rule %d expression is invalid: %w", rule.ID, err)
		}
	}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
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
	}
	return nil
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
