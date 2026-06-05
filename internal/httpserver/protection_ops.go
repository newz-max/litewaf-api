package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
	"litewaf-api/internal/publish"
)

const sampleLimit = 5

type legacyProtectionCandidate struct {
	Store    string
	Module   string
	Category string
	Ref      string
	Rule     model.ProtectionRule
}

func (h handlers) protectionRuleMigrationHealth(w http.ResponseWriter, r *http.Request) {
	item, err := h.buildProtectionRuleMigrationHealth(r.Context())
	h.writeItem(w, item, err)
}

func (h handlers) buildProtectionRuleMigrationHealth(ctx context.Context) (model.ProtectionRuleMigrationHealth, error) {
	protectionRules, err := h.app.Store.ListProtectionRules(ctx)
	if err != nil {
		return model.ProtectionRuleMigrationHealth{}, err
	}
	candidates, err := h.legacyProtectionCandidates(ctx)
	if err != nil {
		return model.ProtectionRuleMigrationHealth{}, err
	}
	health := buildProtectionRuleMigrationHealth(protectionRules, candidates)
	health.GeneratedAt = time.Now().UTC()
	return health, nil
}

func (h handlers) legacyProtectionCandidates(ctx context.Context) ([]legacyProtectionCandidate, error) {
	var candidates []legacyProtectionCandidate
	rateLimits, err := h.app.Store.ListRateLimitRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range rateLimits {
		candidates = append(candidates, legacyProtectionCandidate{
			Store:    "rate_limits",
			Module:   protectionrules.ModuleCC,
			Category: protectionrules.CategoryRateLimit,
			Ref:      protectionrules.LegacyRef("rate_limits", item.ID),
			Rule:     publish.CCProtectionFromRateLimit(item),
		})
	}
	uploadRules, err := h.app.Store.ListUploadProtectionRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range uploadRules {
		candidates = append(candidates, legacyProtectionCandidate{
			Store:    "upload_protection_rules",
			Module:   protectionrules.ModuleUpload,
			Category: protectionrules.CategoryUpload,
			Ref:      protectionrules.LegacyRef("upload_protection_rules", item.ID),
			Rule:     publish.UploadProtectionFromRule(item),
		})
	}
	botRules, err := h.app.Store.ListBotProtectionRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range botRules {
		candidates = append(candidates, legacyProtectionCandidate{
			Store:    "bot_protection_rules",
			Module:   protectionrules.ModuleBot,
			Category: protectionrules.CategoryChallenge,
			Ref:      protectionrules.LegacyRef("bot_protection_rules", item.ID),
			Rule:     publish.BotProtectionFromRule(item),
		})
	}
	dynamicRules, err := h.app.Store.ListDynamicProtectionRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range dynamicRules {
		candidates = append(candidates, legacyProtectionCandidate{
			Store:    "dynamic_protection_rules",
			Module:   protectionrules.ModuleDynamic,
			Category: item.Category,
			Ref:      protectionrules.LegacyRef("dynamic_protection_rules", item.ID),
			Rule:     publish.DynamicProtectionFromRule(item),
		})
	}
	return candidates, nil
}

func buildProtectionRuleMigrationHealth(protectionRules []model.ProtectionRule, candidates []legacyProtectionCandidate) model.ProtectionRuleMigrationHealth {
	rulesByRef := map[string][]model.ProtectionRule{}
	for _, rule := range protectionRules {
		rule = protectionrules.Normalize(rule)
		if rule.LegacyRef != "" {
			rulesByRef[rule.LegacyRef] = append(rulesByRef[rule.LegacyRef], rule)
		}
	}
	candidatesByRef := map[string]legacyProtectionCandidate{}
	for _, candidate := range candidates {
		candidatesByRef[candidate.Ref] = candidate
	}

	storeStates := map[string]*model.LegacyProtectionStoreState{}
	health := model.ProtectionRuleMigrationHealth{
		ProtectionRules: model.ProtectionRuleHealthSummary{
			ByModule:          map[string]int{},
			ByCategory:        map[string]int{},
			BySource:          map[string]int{},
			ByMigrationStatus: map[string]int{},
			BySite:            map[string]int{},
		},
		LegacyStores: []model.LegacyProtectionStoreState{},
		Issues:       []model.ProtectionRuleHealthIssue{},
		Backfill: model.BackfillHealthState{
			Status:         "unknown",
			Command:        "go run ./cmd/litewaf-api backfill-protection-rules",
			Recommendation: "当前版本未记录最近一次 backfill 运行结果；可根据缺失项在维护窗口内重复执行幂等 backfill。",
		},
		RemediationHints: []string{},
	}

	for _, rule := range protectionRules {
		rule = protectionrules.Normalize(rule)
		health.ProtectionRules.Total++
		if rule.Enabled {
			health.ProtectionRules.Enabled++
		} else {
			health.ProtectionRules.Disabled++
		}
		health.ProtectionRules.ByModule[emptyKey(rule.Module)]++
		health.ProtectionRules.ByCategory[emptyKey(rule.Category)]++
		health.ProtectionRules.BySource[emptyKey(rule.Source)]++
		health.ProtectionRules.ByMigrationStatus[emptyKey(rule.MigrationStatus)]++
		health.ProtectionRules.BySite[strconv.FormatInt(rule.SiteID, 10)]++
	}

	for _, candidate := range candidates {
		state := ensureLegacyState(storeStates, candidate)
		state.Total++
		if candidate.Rule.Enabled {
			state.Enabled++
		}
		matches := rulesByRef[candidate.Ref]
		if len(matches) == 0 {
			state.Missing++
			state.MissingSamples = appendSample(state.MissingSamples, candidate.Ref)
			continue
		}
		state.Migrated++
		if len(matches) > 1 {
			state.Duplicates += len(matches)
		}
		if legacyConflict(candidate.Rule, matches[0]) {
			state.Conflicts++
		}
	}

	for ref, rules := range rulesByRef {
		storeName := legacyStoreFromRef(ref)
		state := storeStates[storeName]
		if state == nil {
			state = &model.LegacyProtectionStoreState{Store: storeName}
			storeStates[storeName] = state
		}
		if _, ok := candidatesByRef[ref]; !ok {
			state.Orphaned += len(rules)
			state.OrphanSamples = appendSample(state.OrphanSamples, ref)
		}
	}

	for _, state := range sortedLegacyStates(storeStates) {
		health.LegacyStores = append(health.LegacyStores, state)
		if state.Missing > 0 {
			health.Issues = append(health.Issues, model.ProtectionRuleHealthIssue{
				Type:           "missing_migration",
				Severity:       "warning",
				Store:          state.Store,
				Module:         state.Module,
				Count:          state.Missing,
				Samples:        state.MissingSamples,
				Message:        fmt.Sprintf("%s 有 %d 条旧记录尚未迁移到 protection_rules。", state.Store, state.Missing),
				Recommendation: "在维护窗口内重复执行幂等 backfill，并复查模块列表和发布预览兼容计数。",
			})
		}
		if state.Orphaned > 0 {
			health.Issues = append(health.Issues, model.ProtectionRuleHealthIssue{
				Type:           "orphaned_migration",
				Severity:       "warning",
				Store:          state.Store,
				Module:         state.Module,
				Count:          state.Orphaned,
				Samples:        state.OrphanSamples,
				Message:        fmt.Sprintf("%s 有 %d 条 migrated protection_rules 找不到旧来源。", state.Store, state.Orphaned),
				Recommendation: "先确认旧来源是否已人工清理或回滚，再决定是否保留 migrated 记录作为新主数据。",
			})
		}
		if state.Duplicates > 0 {
			health.Issues = append(health.Issues, model.ProtectionRuleHealthIssue{
				Type:           "duplicate_legacy_ref",
				Severity:       "error",
				Store:          state.Store,
				Module:         state.Module,
				Count:          state.Duplicates,
				Message:        fmt.Sprintf("%s 存在重复 legacy_ref 映射。", state.Store),
				Recommendation: "不要自动删除；先人工确认重复记录的来源、启用状态和发布时间。",
			})
		}
		if state.Conflicts > 0 {
			health.Issues = append(health.Issues, model.ProtectionRuleHealthIssue{
				Type:           "migration_conflict",
				Severity:       "warning",
				Store:          state.Store,
				Module:         state.Module,
				Count:          state.Conflicts,
				Message:        fmt.Sprintf("%s 有 %d 条迁移记录与旧来源有效配置不一致。", state.Store, state.Conflicts),
				Recommendation: "以模块入口为主确认期望配置，再决定同步旧来源、保留差异或进入旧入口弱化阶段。",
			})
		}
	}
	if len(health.Issues) == 0 {
		health.Backfill.Status = "healthy"
		health.Backfill.Recommendation = "未发现旧记录缺失、孤儿迁移、重复 legacy_ref 或迁移冲突。"
		health.RemediationHints = append(health.RemediationHints, "当前迁移健康检查未发现需要处理的问题。")
	} else {
		health.Backfill.Status = "attention_required"
		health.RemediationHints = append(health.RemediationHints,
			"优先处理 missing_migration，再复查 duplicate_legacy_ref 和 migration_conflict。",
			"本接口只读，不会自动修改旧表、protection_rules 或发布配置。",
		)
	}
	return health
}

func ensureLegacyState(states map[string]*model.LegacyProtectionStoreState, candidate legacyProtectionCandidate) *model.LegacyProtectionStoreState {
	state := states[candidate.Store]
	if state == nil {
		state = &model.LegacyProtectionStoreState{
			Store:          candidate.Store,
			Module:         candidate.Module,
			Category:       candidate.Category,
			MissingSamples: []string{},
			OrphanSamples:  []string{},
		}
		states[candidate.Store] = state
	}
	if state.Module == "" {
		state.Module = candidate.Module
	}
	if state.Category == "" {
		state.Category = candidate.Category
	}
	return state
}

func sortedLegacyStates(states map[string]*model.LegacyProtectionStoreState) []model.LegacyProtectionStoreState {
	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]model.LegacyProtectionStoreState, 0, len(keys))
	for _, key := range keys {
		out = append(out, *states[key])
	}
	return out
}

func legacyConflict(expected model.ProtectionRule, actual model.ProtectionRule) bool {
	expected = comparableProtectionRule(expected)
	actual = comparableProtectionRule(actual)
	return !reflect.DeepEqual(expected, actual)
}

func comparableProtectionRule(rule model.ProtectionRule) model.ProtectionRule {
	rule = protectionrules.Normalize(rule)
	rule.ID = 0
	rule.Name = ""
	rule.Source = ""
	rule.MigrationStatus = ""
	rule.LegacyRef = ""
	rule.CreatedAt = time.Time{}
	rule.UpdatedAt = time.Time{}
	return rule
}

func legacyStoreFromRef(ref string) string {
	storeName, _, ok := strings.Cut(ref, ":")
	if !ok || storeName == "" {
		return "unknown"
	}
	return storeName
}

func appendSample(samples []string, value string) []string {
	if value == "" || len(samples) >= sampleLimit {
		return samples
	}
	for _, sample := range samples {
		if sample == value {
			return samples
		}
	}
	return append(samples, value)
}

func emptyKey(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func buildPublishCompatibilityDiagnostics(protectionRules []model.ProtectionRule, rateLimits []model.RateLimitRule, uploadRules []model.UploadProtectionRule, botRules []model.BotProtectionRule, dynamicRules []model.DynamicProtectionRule) model.PublishCompatibilityDiagnostics {
	diagnostics := model.PublishCompatibilityDiagnostics{
		ProtectionRules: len(protectionRules),
		RateLimits:      len(rateLimits),
		LegacyModules: map[string]int{
			"upload_protection_rules":  len(uploadRules),
			"bot_protection_rules":     len(botRules),
			"dynamic_protection_rules": len(dynamicRules),
		},
		ByModule: map[string]model.CompatibilityCounts{},
		Warnings: []string{},
	}
	seen := map[string]bool{}
	for _, rule := range protectionRules {
		rule = protectionrules.Normalize(rule)
		counts := diagnostics.ByModule[rule.Module]
		counts.ProtectionRules++
		switch rule.MigrationStatus {
		case protectionrules.StatusMigrated:
			counts.Migrated++
		default:
			counts.Native++
		}
		diagnostics.ByModule[rule.Module] = counts
		if rule.LegacyRef != "" {
			seen[rule.LegacyRef] = true
		}
	}
	addLegacy := func(module string, total int, refs []string) {
		counts := diagnostics.ByModule[module]
		counts.LegacyStore += total
		for _, ref := range refs {
			if seen[ref] {
				counts.Deduplicated++
				diagnostics.Deduplicated++
			} else {
				counts.LegacyFallback++
			}
		}
		diagnostics.ByModule[module] = counts
	}
	addLegacy(protectionrules.ModuleCC, len(rateLimits), legacyRefs("rate_limits", rateLimitIDs(rateLimits)))
	addLegacy(protectionrules.ModuleUpload, len(uploadRules), legacyRefs("upload_protection_rules", uploadRuleIDs(uploadRules)))
	addLegacy(protectionrules.ModuleBot, len(botRules), legacyRefs("bot_protection_rules", botRuleIDs(botRules)))
	addLegacy(protectionrules.ModuleDynamic, len(dynamicRules), legacyRefs("dynamic_protection_rules", dynamicRuleIDs(dynamicRules)))
	if diagnostics.RateLimits > 0 || len(uploadRules)+len(botRules)+len(dynamicRules) > 0 {
		diagnostics.Warnings = append(diagnostics.Warnings, "发布仍保留旧字段和旧模块兼容输出，网关回滚与混合版本依赖这些字段。")
	}
	if diagnostics.Deduplicated > 0 {
		diagnostics.Warnings = append(diagnostics.Warnings, fmt.Sprintf("已通过 legacy_ref 避免 %d 条旧来源重复生成有效 protection_rules。", diagnostics.Deduplicated))
	}
	return diagnostics
}

func legacyRefs(kind string, ids []int64) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, protectionrules.LegacyRef(kind, id))
	}
	return out
}

func rateLimitIDs(items []model.RateLimitRule) []int64 {
	out := make([]int64, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}

func uploadRuleIDs(items []model.UploadProtectionRule) []int64 {
	out := make([]int64, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}

func botRuleIDs(items []model.BotProtectionRule) []int64 {
	out := make([]int64, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}

func dynamicRuleIDs(items []model.DynamicProtectionRule) []int64 {
	out := make([]int64, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}
