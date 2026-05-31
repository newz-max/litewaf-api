package attackmeta

import (
	"strings"

	"litewaf-api/internal/model"
)

const (
	Module   = "attack-protection"
	Category = "managed"
)

type Definition struct {
	Type  string
	Group string
}

var definitions = map[string]Definition{
	"sqli":           {Type: "sqli", Group: "SQL 注入防护"},
	"xss":            {Type: "xss", Group: "XSS 防护"},
	"rce":            {Type: "rce", Group: "RCE 防护"},
	"path-traversal": {Type: "path-traversal", Group: "路径穿越防护"},
}

func SupportedTypes() []string {
	return []string{"sqli", "xss", "rce", "path-traversal"}
}

func NormalizeRule(rule model.Rule) model.Rule {
	rule.Module = strings.ToLower(strings.TrimSpace(rule.Module))
	rule.Category = strings.ToLower(strings.TrimSpace(rule.Category))
	rule.AttackType = strings.ToLower(strings.TrimSpace(rule.AttackType))
	rule.Group = strings.TrimSpace(rule.Group)
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	if rule.Module == "" && IsManagedAttackRule(rule) {
		rule.Module = Module
	}
	if rule.Category == "" && rule.Module == Module {
		rule.Category = Category
	}
	if rule.AttackType == "" {
		rule.AttackType = InferAttackType(rule)
	}
	if rule.Group == "" {
		rule.Group = GroupName(rule.AttackType)
	}
	return rule
}

func IsManagedAttackRule(rule model.Rule) bool {
	if rule.Module == Module && rule.Category == Category {
		return true
	}
	return InferAttackType(rule) != ""
}

func InferAttackType(rule model.Rule) string {
	ruleType := strings.ToLower(strings.TrimSpace(rule.Type))
	target := strings.ToLower(strings.TrimSpace(rule.Target))
	name := strings.ToLower(strings.TrimSpace(rule.Name))
	switch {
	case ruleType == "sqli":
		return "sqli"
	case ruleType == "xss":
		return "xss"
	case ruleType == "rce" && (strings.Contains(target, "normalized") || strings.Contains(name, "traversal") || strings.Contains(name, "path traversal")):
		return "path-traversal"
	case ruleType == "rce":
		return "rce"
	default:
		return ""
	}
}

func GroupName(attackType string) string {
	if def, ok := definitions[attackType]; ok {
		return def.Group
	}
	return "未分类攻击防护"
}

func ValidAttackType(value string) bool {
	_, ok := definitions[value]
	return ok
}
