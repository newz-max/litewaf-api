package defaults

import (
	"context"

	"litewaf-api/internal/model"
)

const RuleSetVersion = "litewaf-default-rules-v1"

var DefaultRules = []model.Rule{
	{
		Name:       "LiteWaf SQLi baseline",
		Type:       "sqli",
		Target:     "args",
		Action:     "block",
		Expression: `(?i)(union\s+select|or\s+1=1|sleep\s*\(|benchmark\s*\()`,
		Score:      80,
		Enabled:    true,
	},
	{
		Name:       "LiteWaf XSS baseline",
		Type:       "xss",
		Target:     "args",
		Action:     "block",
		Expression: `(?i)(<script|javascript:|onerror\s*=|onload\s*=)`,
		Score:      80,
		Enabled:    true,
	},
	{
		Name:       "LiteWaf RCE baseline",
		Type:       "rce",
		Target:     "args",
		Action:     "block",
		Expression: `(?i)(;\s*(cat|curl|wget|bash|sh)\b|\|\s*(bash|sh)\b|\$\(|/bin/(bash|sh))`,
		Score:      90,
		Enabled:    true,
	},
	{
		Name:       "LiteWaf normalized traversal baseline",
		Type:       "rce",
		Target:     "normalized_uri",
		Action:     "block",
		Expression: `(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self/environ)`,
		Score:      70,
		Enabled:    true,
	},
}

var LegacyRuleNames = map[string]string{
	"MVP SQLi baseline": "LiteWaf SQLi baseline",
	"MVP XSS baseline":  "LiteWaf XSS baseline",
}

type RuleStore interface {
	ListRules(context.Context) ([]model.Rule, error)
	CreateRule(context.Context, model.Rule) (model.Rule, error)
	UpdateRule(context.Context, int64, model.Rule) (model.Rule, error)
	DeleteRule(context.Context, int64) error
}

func SeedRules(ctx context.Context, store RuleStore) error {
	existing, err := store.ListRules(ctx)
	if err != nil {
		return err
	}

	byName := map[string]model.Rule{}
	for _, rule := range existing {
		byName[rule.Name] = rule
	}

	for _, rule := range DefaultRules {
		if current, ok := byName[rule.Name]; ok {
			if _, err := store.UpdateRule(ctx, current.ID, rule); err != nil {
				return err
			}
			for legacyName, currentName := range LegacyRuleNames {
				if currentName == rule.Name {
					if legacy, ok := byName[legacyName]; ok {
						if err := store.DeleteRule(ctx, legacy.ID); err != nil {
							return err
						}
					}
				}
			}
			continue
		}
		upgraded := false
		for legacyName, currentName := range LegacyRuleNames {
			if currentName != rule.Name {
				continue
			}
			if current, ok := byName[legacyName]; ok {
				if _, err := store.UpdateRule(ctx, current.ID, rule); err != nil {
					return err
				}
				byName[rule.Name] = rule
				upgraded = true
				break
			}
		}
		if upgraded {
			continue
		}
		if _, err := store.CreateRule(ctx, rule); err != nil {
			return err
		}
	}

	return nil
}
