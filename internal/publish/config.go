package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

func Generate(ctx context.Context, dataStore store.Store, version string) (GatewayConfig, []byte, string, error) {
	sites, err := dataStore.ListSites(ctx)
	if err != nil {
		return GatewayConfig{}, nil, "", err
	}
	rules, err := dataStore.ListRules(ctx)
	if err != nil {
		return GatewayConfig{}, nil, "", err
	}
	policies, err := dataStore.ListPolicies(ctx)
	if err != nil {
		return GatewayConfig{}, nil, "", err
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

	config := GatewayConfig{
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Sites:       []GatewaySite{},
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

	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return GatewayConfig{}, nil, "", err
	}
	sum := sha256.Sum256(payload)
	return config, payload, hex.EncodeToString(sum[:]), nil
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
