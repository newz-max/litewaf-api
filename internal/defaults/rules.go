package defaults

import (
	"context"
	"encoding/json"

	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/model"
)

const RuleSetVersion = "litewaf-default-rules-v1"
const RulePackageID = "litewaf-default-rules"
const RulePackageLicense = "Apache-2.0"

var DefaultRules = []model.Rule{
	{
		Name:       "LiteWaf SQLi baseline",
		Type:       "sqli",
		Target:     "args",
		Action:     "block",
		Expression: `(?i)(union\s+select|or\s+1=1|sleep\s*\(|benchmark\s*\()`,
		Score:      80,
		Enabled:    true,
		Module:     attackmeta.Module,
		Category:   attackmeta.Category,
		AttackType: "sqli",
		Group:      attackmeta.GroupName("sqli"),
		Priority:   100,
	},
	{
		Name:       "LiteWaf XSS baseline",
		Type:       "xss",
		Target:     "args",
		Action:     "block",
		Expression: `(?i)(<script|javascript:|onerror\s*=|onload\s*=)`,
		Score:      80,
		Enabled:    true,
		Module:     attackmeta.Module,
		Category:   attackmeta.Category,
		AttackType: "xss",
		Group:      attackmeta.GroupName("xss"),
		Priority:   110,
	},
	{
		Name:       "LiteWaf RCE baseline",
		Type:       "rce",
		Target:     "args",
		Action:     "block",
		Expression: `(?i)(;\s*(cat|curl|wget|bash|sh)\b|\|\s*(bash|sh)\b|\$\(|/bin/(bash|sh))`,
		Score:      90,
		Enabled:    true,
		Module:     attackmeta.Module,
		Category:   attackmeta.Category,
		AttackType: "rce",
		Group:      attackmeta.GroupName("rce"),
		Priority:   120,
	},
	{
		Name:       "LiteWaf normalized traversal baseline",
		Type:       "path-traversal",
		Target:     "normalized_path",
		Action:     "block",
		Expression: `(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self/environ)`,
		Score:      70,
		Enabled:    true,
		Module:     attackmeta.Module,
		Category:   attackmeta.Category,
		AttackType: "path-traversal",
		Group:      attackmeta.GroupName("path-traversal"),
		Priority:   130,
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
		rule = attackmeta.NormalizeRule(rule)
		attachDefaultPackageOrigin(&rule)
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

func DefaultRulePackage() model.RulePackage {
	rules := make([]model.Rule, 0, len(DefaultRules))
	for _, rule := range DefaultRules {
		rule = attackmeta.NormalizeRule(rule)
		attachDefaultPackageOrigin(&rule)
		rules = append(rules, rule)
	}
	return model.RulePackage{
		Metadata: model.RulePackageMetadata{
			ID:              RulePackageID,
			Name:            "LiteWaf default managed rules",
			Version:         RuleSetVersion,
			Author:          "LiteWaf",
			License:         RulePackageLicense,
			Compatibility:   "litewaf-rule-package-v1",
			SignatureStatus: "unsigned",
			RuleCount:       len(rules),
			Warnings:        []string{"built-in default package is unsigned"},
		},
		Defaults: model.RulePackageDefaults{
			Enabled:      true,
			ReviewStatus: "approved",
		},
		Rules: rules,
	}
}

func DefaultRulePackageJSON() []byte {
	payload, _ := json.MarshalIndent(DefaultRulePackage(), "", "  ")
	return payload
}

func attachDefaultPackageOrigin(rule *model.Rule) {
	rule.PackageID = RulePackageID
	rule.PackageVersion = RuleSetVersion
	if rule.PackageRuleID == "" {
		rule.PackageRuleID = rule.Type + "-" + rule.Target
	}
	rule.SignatureStatus = "unsigned"
	rule.ReviewStatus = "approved"
	if rule.SourceChecksum == "" {
		rule.SourceChecksum = RuleSetVersion + ":" + rule.PackageRuleID
	}
}
