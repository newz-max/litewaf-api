package protectionrules

import (
	"fmt"
	"net"
	"strings"

	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/model"
)

const (
	SourceNative      = "protection_rules"
	SourceLegacy      = "legacy"
	StatusNative      = "native"
	StatusMigrated    = "migrated"
	StatusLegacyOnly  = "legacy-only"
	ModuleCC          = "cc-protection"
	ModuleAccess      = "access-control"
	ModuleUpload      = "upload-protection"
	ModuleBot         = "bot-protection"
	ModuleDynamic     = "dynamic-protection"
	ModuleAttack      = "attack-protection"
	CategoryRateLimit = "rate-limit"
	CategoryAccess    = "access-control"
	CategoryUpload    = "upload"
	CategoryChallenge = "challenge"
	CategoryManaged   = "managed"
)

func LegacyRef(kind string, id int64) string {
	return fmt.Sprintf("%s:%d", kind, id)
}

func Normalize(rule model.ProtectionRule) model.ProtectionRule {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Module = strings.TrimSpace(rule.Module)
	rule.Category = strings.TrimSpace(rule.Category)
	rule.Match.Path = strings.TrimSpace(rule.Match.Path)
	rule.Match.PathMatch = strings.ToLower(strings.TrimSpace(rule.Match.PathMatch))
	rule.Match.Target = strings.ToLower(strings.TrimSpace(rule.Match.Target))
	rule.Match.Value = strings.TrimSpace(rule.Match.Value)
	rule.Match.Operator = strings.ToLower(strings.TrimSpace(rule.Match.Operator))
	rule.Match.HeaderName = strings.TrimSpace(rule.Match.HeaderName)
	rule.Match.Host = strings.ToLower(strings.TrimSpace(rule.Match.Host))
	rule.Match.Methods = normalizeHTTPMethods(rule.Match.Methods)
	rule.Limit.Counter = strings.ToLower(strings.TrimSpace(rule.Limit.Counter))
	if rule.Upload != nil {
		rule.Upload.Extensions = normalizeExtensions(rule.Upload.Extensions)
	}
	if rule.Challenge != nil {
		rule.Challenge.Mode = strings.ToLower(strings.TrimSpace(rule.Challenge.Mode))
		rule.Challenge.FailureAction = strings.ToLower(strings.TrimSpace(rule.Challenge.FailureAction))
	}
	if rule.Dynamic != nil {
		rule.Dynamic.Mode = strings.ToLower(strings.TrimSpace(rule.Dynamic.Mode))
		rule.Dynamic.TokenPlacement = strings.ToLower(strings.TrimSpace(rule.Dynamic.TokenPlacement))
		rule.Dynamic.FailureAction = strings.ToLower(strings.TrimSpace(rule.Dynamic.FailureAction))
		rule.Dynamic.MutationMarker = strings.ToLower(strings.TrimSpace(rule.Dynamic.MutationMarker))
		rule.Dynamic.OverflowAction = strings.ToLower(strings.TrimSpace(rule.Dynamic.OverflowAction))
	}
	rule.Action.Type = strings.ToLower(strings.TrimSpace(rule.Action.Type))
	rule.Source = strings.TrimSpace(rule.Source)
	rule.MigrationStatus = strings.TrimSpace(rule.MigrationStatus)
	rule.LegacyRef = strings.TrimSpace(rule.LegacyRef)
	if rule.Priority <= 0 {
		rule.Priority = 100
	}
	if rule.Source == "" {
		rule.Source = SourceNative
	}
	if rule.MigrationStatus == "" {
		rule.MigrationStatus = StatusNative
	}
	return rule
}

func Validate(rule model.ProtectionRule) error {
	rule = Normalize(rule)
	if rule.Name == "" {
		return fmt.Errorf("protection rule name is required")
	}
	if rule.Priority < 0 {
		return fmt.Errorf("protection rule priority cannot be negative")
	}
	switch rule.Module {
	case ModuleCC:
		return validateCC(rule)
	case ModuleAccess:
		return validateAccess(rule)
	case ModuleUpload:
		return validateUpload(rule)
	case ModuleBot:
		return validateBot(rule)
	case ModuleDynamic:
		return validateDynamic(rule)
	case ModuleAttack:
		return validateAttack(rule)
	default:
		return fmt.Errorf("protection rule module is unsupported")
	}
}

func FromRateLimit(item model.RateLimitRule) model.ProtectionRule {
	path, pathMatch := ccProtectionPath(item)
	return Normalize(model.ProtectionRule{
		ID:              item.ID,
		Name:            item.Name,
		Module:          ModuleCC,
		Category:        CategoryRateLimit,
		SiteID:          item.SiteID,
		Enabled:         item.Enabled,
		Priority:        100,
		Source:          SourceLegacy,
		MigrationStatus: StatusLegacyOnly,
		LegacyRef:       LegacyRef("rate_limits", item.ID),
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
		Action:    model.ProtectionRuleAction{Type: ccProtectionAction(item)},
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	})
}

func ToRateLimit(rule model.ProtectionRule) model.RateLimitRule {
	rule = Normalize(rule)
	return model.RateLimitRule{
		ID:          rule.ID,
		Name:        rule.Name,
		Scope:       ccRateLimitScope(rule.Limit.Counter),
		MatchValue:  ccRateLimitMatchValue(rule.Match),
		PathMatch:   rule.Match.PathMatch,
		Methods:     cloneStrings(rule.Match.Methods),
		Threshold:   rule.Limit.Threshold,
		WindowSec:   rule.Limit.WindowSec,
		Action:      ccRateLimitLegacyAction(rule.Action.Type),
		CCAction:    rule.Action.Type,
		BanDuration: rule.Limit.BanDurationSec,
		SiteID:      rule.SiteID,
		Enabled:     rule.Enabled,
		CreatedAt:   rule.CreatedAt,
		UpdatedAt:   rule.UpdatedAt,
	}
}

func FromAccessList(item model.AccessListEntry) model.ProtectionRule {
	return Normalize(model.ProtectionRule{
		ID:              item.ID,
		Name:            item.Name,
		Module:          ModuleAccess,
		Category:        CategoryAccess,
		SiteID:          item.SiteID,
		Enabled:         item.Enabled,
		Priority:        priority(item.Priority),
		Source:          SourceLegacy,
		MigrationStatus: StatusLegacyOnly,
		LegacyRef:       LegacyRef("access_lists", item.ID),
		Match:           accessControlMatch(item),
		Action:          model.ProtectionRuleAction{Type: accessControlAction(item)},
		CreatedAt:       item.CreatedAt,
		UpdatedAt:       item.UpdatedAt,
	})
}

func ToAccessList(rule model.ProtectionRule) model.AccessListEntry {
	rule = Normalize(rule)
	target := rule.Match.Target
	value := rule.Match.Value
	headerName := rule.Match.HeaderName
	operator := rule.Match.Operator
	switch target {
	case "path":
		target = "uri"
		value = rule.Match.Path
		operator = rule.Match.PathMatch
	case "host":
		value = rule.Match.Host
	}
	kind := "blacklist"
	if rule.Action.Type == "allow" {
		kind = "whitelist"
	}
	return model.AccessListEntry{
		ID:            rule.ID,
		Name:          rule.Name,
		Kind:          kind,
		Target:        target,
		Value:         value,
		MatchOperator: operator,
		HeaderName:    headerName,
		Action:        accessControlActionFromRule(rule.Action.Type),
		SiteID:        rule.SiteID,
		Enabled:       rule.Enabled,
		Priority:      priority(rule.Priority),
		CreatedAt:     rule.CreatedAt,
		UpdatedAt:     rule.UpdatedAt,
	}
}

func FromUpload(item model.UploadProtectionRule) model.ProtectionRule {
	path := item.Path
	if path == "" {
		path = "/"
	}
	pathMatch := item.PathMatch
	if pathMatch == "" {
		pathMatch = "prefix"
	}
	return Normalize(model.ProtectionRule{
		ID:              item.ID,
		Name:            item.Name,
		Module:          ModuleUpload,
		Category:        CategoryUpload,
		SiteID:          item.SiteID,
		Enabled:         item.Enabled,
		Priority:        priority(item.Priority),
		Source:          SourceLegacy,
		MigrationStatus: StatusLegacyOnly,
		LegacyRef:       LegacyRef("upload_protection_rules", item.ID),
		Match: model.ProtectionRuleMatch{
			Path:      path,
			PathMatch: pathMatch,
			Methods:   cloneStrings(item.Methods),
			Target:    "upload",
		},
		Upload: &model.ProtectionRuleUpload{
			Extensions: cloneStrings(item.Extensions),
			MaxBytes:   item.MaxBytes,
		},
		Action:    model.ProtectionRuleAction{Type: item.Action},
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	})
}

func ToUpload(rule model.ProtectionRule) model.UploadProtectionRule {
	rule = Normalize(rule)
	upload := model.ProtectionRuleUpload{}
	if rule.Upload != nil {
		upload = *rule.Upload
	}
	return model.UploadProtectionRule{
		ID:         rule.ID,
		Name:       rule.Name,
		Path:       rule.Match.Path,
		PathMatch:  rule.Match.PathMatch,
		Methods:    cloneStrings(rule.Match.Methods),
		Extensions: cloneStrings(upload.Extensions),
		MaxBytes:   upload.MaxBytes,
		Action:     rule.Action.Type,
		SiteID:     rule.SiteID,
		Enabled:    rule.Enabled,
		Priority:   priority(rule.Priority),
		CreatedAt:  rule.CreatedAt,
		UpdatedAt:  rule.UpdatedAt,
	}
}

func FromBot(item model.BotProtectionRule) model.ProtectionRule {
	path := item.Path
	if path == "" {
		path = "/"
	}
	pathMatch := item.PathMatch
	if pathMatch == "" {
		pathMatch = "prefix"
	}
	mode := item.ChallengeMode
	if mode == "" {
		mode = "js-challenge"
	}
	verifyTTL := item.VerifyTTL
	if verifyTTL == 0 {
		verifyTTL = 300
	}
	failureAction := item.FailureAction
	if failureAction == "" {
		failureAction = "block"
	}
	return Normalize(model.ProtectionRule{
		ID:              item.ID,
		Name:            item.Name,
		Module:          ModuleBot,
		Category:        CategoryChallenge,
		SiteID:          item.SiteID,
		Enabled:         item.Enabled,
		Priority:        priority(item.Priority),
		Source:          SourceLegacy,
		MigrationStatus: StatusLegacyOnly,
		LegacyRef:       LegacyRef("bot_protection_rules", item.ID),
		Match: model.ProtectionRuleMatch{
			Path:      path,
			PathMatch: pathMatch,
			Methods:   cloneStrings(item.Methods),
			Target:    "path",
		},
		Challenge: &model.ProtectionRuleChallenge{
			Mode:          mode,
			VerifyTTL:     verifyTTL,
			FailureAction: failureAction,
		},
		Action:    model.ProtectionRuleAction{Type: failureAction},
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	})
}

func ToBot(rule model.ProtectionRule) model.BotProtectionRule {
	rule = Normalize(rule)
	challenge := model.ProtectionRuleChallenge{}
	if rule.Challenge != nil {
		challenge = *rule.Challenge
	}
	return model.BotProtectionRule{
		ID:            rule.ID,
		Name:          rule.Name,
		Path:          rule.Match.Path,
		PathMatch:     rule.Match.PathMatch,
		Methods:       cloneStrings(rule.Match.Methods),
		ChallengeMode: challenge.Mode,
		VerifyTTL:     challenge.VerifyTTL,
		FailureAction: challenge.FailureAction,
		SiteID:        rule.SiteID,
		Enabled:       rule.Enabled,
		Priority:      priority(rule.Priority),
		CreatedAt:     rule.CreatedAt,
		UpdatedAt:     rule.UpdatedAt,
	}
}

func FromDynamic(item model.DynamicProtectionRule) model.ProtectionRule {
	path := item.Path
	if path == "" {
		path = "/"
	}
	pathMatch := item.PathMatch
	if pathMatch == "" {
		pathMatch = "prefix"
	}
	category := item.Category
	if category == "" {
		category = "dynamic-token"
	}
	dynamic := DynamicConfig(item)
	action := dynamic.FailureAction
	if category == "waiting-room" {
		action = dynamic.OverflowAction
	}
	if category == "page-mutation" {
		action = "log-only"
	}
	return Normalize(model.ProtectionRule{
		ID:              item.ID,
		Name:            item.Name,
		Module:          ModuleDynamic,
		Category:        category,
		SiteID:          item.SiteID,
		Enabled:         item.Enabled,
		Priority:        priority(item.Priority),
		Source:          SourceLegacy,
		MigrationStatus: StatusLegacyOnly,
		LegacyRef:       LegacyRef("dynamic_protection_rules", item.ID),
		Match: model.ProtectionRuleMatch{
			Path:      path,
			PathMatch: pathMatch,
			Methods:   cloneStrings(item.Methods),
			Target:    "path",
		},
		Dynamic:   &dynamic,
		Action:    model.ProtectionRuleAction{Type: action},
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	})
}

func ToDynamic(rule model.ProtectionRule) model.DynamicProtectionRule {
	rule = Normalize(rule)
	dynamic := model.ProtectionRuleDynamic{}
	if rule.Dynamic != nil {
		dynamic = *rule.Dynamic
	}
	category := rule.Category
	if category == "" {
		category = dynamic.Mode
	}
	return model.DynamicProtectionRule{
		ID:               rule.ID,
		Name:             rule.Name,
		Category:         category,
		Path:             rule.Match.Path,
		PathMatch:        rule.Match.PathMatch,
		Methods:          cloneStrings(rule.Match.Methods),
		TokenTTL:         dynamic.TokenTTL,
		TokenPlacement:   dynamic.TokenPlacement,
		FailureAction:    dynamic.FailureAction,
		MutationMarker:   dynamic.MutationMarker,
		MutationMaxBytes: dynamic.MutationMaxBytes,
		QueueCapacity:    dynamic.QueueCapacity,
		AdmissionTTL:     dynamic.AdmissionTTL,
		RetryInterval:    dynamic.RetryInterval,
		OverflowAction:   dynamic.OverflowAction,
		SiteID:           rule.SiteID,
		Enabled:          rule.Enabled,
		Priority:         priority(rule.Priority),
		CreatedAt:        rule.CreatedAt,
		UpdatedAt:        rule.UpdatedAt,
	}
}

func FromAttackRule(rule model.Rule) model.ProtectionRule {
	rule = attackmeta.NormalizeRule(rule)
	return Normalize(model.ProtectionRule{
		ID:              rule.ID,
		Name:            rule.Name,
		Module:          ModuleAttack,
		Category:        CategoryManaged,
		SiteID:          0,
		Enabled:         rule.Enabled,
		Priority:        priority(rule.Priority),
		Source:          SourceLegacy,
		MigrationStatus: StatusLegacyOnly,
		LegacyRef:       LegacyRef("rules", rule.ID),
		Match: model.ProtectionRuleMatch{
			Target: rule.Target,
			Value:  rule.Expression,
		},
		Action:    model.ProtectionRuleAction{Type: rule.Action},
		CreatedAt: rule.CreatedAt,
		UpdatedAt: rule.UpdatedAt,
	})
}

func DynamicConfig(item model.DynamicProtectionRule) model.ProtectionRuleDynamic {
	category := item.Category
	if category == "" {
		category = "dynamic-token"
	}
	dynamic := model.ProtectionRuleDynamic{
		Mode:             category,
		TokenTTL:         item.TokenTTL,
		TokenPlacement:   item.TokenPlacement,
		FailureAction:    item.FailureAction,
		MutationMarker:   item.MutationMarker,
		MutationMaxBytes: item.MutationMaxBytes,
		QueueCapacity:    item.QueueCapacity,
		AdmissionTTL:     item.AdmissionTTL,
		RetryInterval:    item.RetryInterval,
		OverflowAction:   item.OverflowAction,
	}
	if dynamic.TokenTTL == 0 {
		dynamic.TokenTTL = 300
	}
	if dynamic.TokenPlacement == "" {
		dynamic.TokenPlacement = "cookie"
	}
	if dynamic.FailureAction == "" {
		dynamic.FailureAction = "block"
	}
	if dynamic.MutationMarker == "" {
		dynamic.MutationMarker = "body-end"
	}
	if dynamic.MutationMaxBytes == 0 {
		dynamic.MutationMaxBytes = 262144
	}
	if dynamic.QueueCapacity == 0 {
		dynamic.QueueCapacity = 100
	}
	if dynamic.AdmissionTTL == 0 {
		dynamic.AdmissionTTL = 300
	}
	if dynamic.RetryInterval == 0 {
		dynamic.RetryInterval = 5
	}
	if dynamic.OverflowAction == "" {
		dynamic.OverflowAction = "waiting-room"
	}
	return dynamic
}

func validateCC(rule model.ProtectionRule) error {
	if rule.Category != CategoryRateLimit {
		return fmt.Errorf("cc protection category must be rate-limit")
	}
	if !strings.HasPrefix(rule.Match.Path, "/") {
		return fmt.Errorf("cc protection path must start with /")
	}
	if !oneOf(rule.Match.PathMatch, "exact", "prefix") {
		return fmt.Errorf("cc protection path_match must be exact or prefix")
	}
	if err := validateMethods(rule.Match.Methods); err != nil {
		return fmt.Errorf("cc protection %w", err)
	}
	if !oneOf(rule.Limit.Counter, "client_ip", "client_ip_path", "global") {
		return fmt.Errorf("cc protection counter is unsupported")
	}
	if rule.Limit.Threshold <= 0 {
		return fmt.Errorf("cc protection threshold must be positive")
	}
	if rule.Limit.WindowSec <= 0 {
		return fmt.Errorf("cc protection window_sec must be positive")
	}
	if rule.Limit.BanDurationSec < 0 {
		return fmt.Errorf("cc protection ban_duration_sec cannot be negative")
	}
	if !oneOf(rule.Action.Type, "log-only", "block", "rate-limit", "ban") {
		return fmt.Errorf("cc protection action is unsupported")
	}
	return nil
}

func validateAccess(rule model.ProtectionRule) error {
	if rule.Category != CategoryAccess {
		return fmt.Errorf("access control category must be access-control")
	}
	if !oneOf(rule.Action.Type, "allow", "log-only", "block") {
		return fmt.Errorf("access control action is unsupported")
	}
	if err := validateMethods(rule.Match.Methods); err != nil {
		return fmt.Errorf("access control %w", err)
	}
	switch rule.Match.Target {
	case "ip":
		if net.ParseIP(rule.Match.Value) == nil {
			return fmt.Errorf("access control ip value is invalid")
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(rule.Match.Value); err != nil {
			return fmt.Errorf("access control cidr value is invalid")
		}
	case "path":
		if !strings.HasPrefix(rule.Match.Path, "/") {
			return fmt.Errorf("access control path must start with /")
		}
		if !oneOf(rule.Match.PathMatch, "exact", "prefix") {
			return fmt.Errorf("access control path_match must be exact or prefix")
		}
	case "header":
		if rule.Match.HeaderName == "" || rule.Match.Value == "" {
			return fmt.Errorf("access control header name and value are required")
		}
		if !oneOf(rule.Match.Operator, "exact", "contains") {
			return fmt.Errorf("access control header operator must be exact or contains")
		}
	case "host":
		if rule.Match.Host == "" {
			return fmt.Errorf("access control host is required")
		}
		if !oneOf(rule.Match.Operator, "exact", "suffix") {
			return fmt.Errorf("access control host operator must be exact or suffix")
		}
	default:
		return fmt.Errorf("access control target is unsupported")
	}
	return nil
}

func validateUpload(rule model.ProtectionRule) error {
	if rule.Category != CategoryUpload {
		return fmt.Errorf("upload protection category must be upload")
	}
	if !strings.HasPrefix(rule.Match.Path, "/") {
		return fmt.Errorf("upload protection path must start with /")
	}
	if !oneOf(rule.Match.PathMatch, "exact", "prefix") {
		return fmt.Errorf("upload protection path_match must be exact or prefix")
	}
	if err := validateMethods(rule.Match.Methods); err != nil {
		return fmt.Errorf("upload protection %w", err)
	}
	if rule.Upload == nil {
		return fmt.Errorf("upload protection config is required")
	}
	if len(rule.Upload.Extensions) == 0 && rule.Upload.MaxBytes <= 0 {
		return fmt.Errorf("upload protection requires extensions or max_bytes")
	}
	for _, extension := range rule.Upload.Extensions {
		if extension == "" || strings.ContainsAny(extension, `/\`) || strings.Contains(extension, "..") {
			return fmt.Errorf("upload protection extension is invalid")
		}
	}
	if rule.Upload.MaxBytes < 0 {
		return fmt.Errorf("upload protection max_bytes cannot be negative")
	}
	if !oneOf(rule.Action.Type, "log-only", "block") {
		return fmt.Errorf("upload protection action is unsupported")
	}
	return nil
}

func validateBot(rule model.ProtectionRule) error {
	if rule.Category != CategoryChallenge {
		return fmt.Errorf("bot protection category must be challenge")
	}
	if !strings.HasPrefix(rule.Match.Path, "/") {
		return fmt.Errorf("bot protection path must start with /")
	}
	if !oneOf(rule.Match.PathMatch, "exact", "prefix") {
		return fmt.Errorf("bot protection path_match must be exact or prefix")
	}
	if err := validateMethods(rule.Match.Methods); err != nil {
		return fmt.Errorf("bot protection %w", err)
	}
	if rule.Challenge == nil {
		return fmt.Errorf("bot protection challenge is required")
	}
	if rule.Challenge.Mode != "js-challenge" {
		return fmt.Errorf("bot protection challenge mode must be js-challenge")
	}
	if rule.Challenge.VerifyTTL <= 0 || rule.Challenge.VerifyTTL > 86400 {
		return fmt.Errorf("bot protection verify_ttl_sec is invalid")
	}
	if !oneOf(rule.Challenge.FailureAction, "log-only", "block") {
		return fmt.Errorf("bot protection failure_action is unsupported")
	}
	if !oneOf(rule.Action.Type, "", rule.Challenge.FailureAction) {
		return fmt.Errorf("bot protection action must match failure_action")
	}
	return nil
}

func validateDynamic(rule model.ProtectionRule) error {
	if !oneOf(rule.Category, "dynamic-token", "page-mutation", "waiting-room") {
		return fmt.Errorf("dynamic protection category is unsupported")
	}
	if !strings.HasPrefix(rule.Match.Path, "/") {
		return fmt.Errorf("dynamic protection path must start with /")
	}
	if !oneOf(rule.Match.PathMatch, "exact", "prefix") {
		return fmt.Errorf("dynamic protection path_match must be exact or prefix")
	}
	if err := validateMethods(rule.Match.Methods); err != nil {
		return fmt.Errorf("dynamic protection %w", err)
	}
	if rule.Dynamic == nil {
		return fmt.Errorf("dynamic protection config is required")
	}
	switch rule.Category {
	case "dynamic-token":
		if rule.Dynamic.TokenTTL <= 0 || rule.Dynamic.TokenTTL > 86400 {
			return fmt.Errorf("dynamic protection token_ttl_sec is invalid")
		}
		if !oneOf(rule.Dynamic.TokenPlacement, "cookie", "header", "query") {
			return fmt.Errorf("dynamic protection token_placement is unsupported")
		}
		if !oneOf(rule.Dynamic.FailureAction, "log-only", "block") {
			return fmt.Errorf("dynamic protection failure_action is unsupported")
		}
	case "page-mutation":
		if !oneOf(rule.Dynamic.MutationMarker, "head-end", "body-end") {
			return fmt.Errorf("dynamic protection mutation_marker is unsupported")
		}
		if rule.Dynamic.MutationMaxBytes <= 0 || rule.Dynamic.MutationMaxBytes > 1048576 {
			return fmt.Errorf("dynamic protection mutation_max_bytes is invalid")
		}
	case "waiting-room":
		if rule.Dynamic.QueueCapacity <= 0 || rule.Dynamic.QueueCapacity > 100000 {
			return fmt.Errorf("dynamic protection queue_capacity is invalid")
		}
		if rule.Dynamic.AdmissionTTL <= 0 || rule.Dynamic.AdmissionTTL > 86400 {
			return fmt.Errorf("dynamic protection admission_ttl_sec is invalid")
		}
		if rule.Dynamic.RetryInterval <= 0 || rule.Dynamic.RetryInterval > 86400 {
			return fmt.Errorf("dynamic protection retry_interval_sec is invalid")
		}
		if !oneOf(rule.Dynamic.OverflowAction, "waiting-room", "block", "log-only") {
			return fmt.Errorf("dynamic protection overflow_action is unsupported")
		}
	}
	return nil
}

func validateAttack(rule model.ProtectionRule) error {
	if rule.Category != CategoryManaged {
		return fmt.Errorf("attack protection category must be managed")
	}
	if !oneOf(rule.Action.Type, "log-only", "block") {
		return fmt.Errorf("attack protection action is unsupported")
	}
	return nil
}

func validateMethods(methods []string) error {
	for _, method := range methods {
		if !oneOf(method, "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") {
			return fmt.Errorf("method is unsupported")
		}
	}
	return nil
}

func accessControlMatch(item model.AccessListEntry) model.ProtectionRuleMatch {
	operator := item.MatchOperator
	if operator == "" {
		operator = defaultAccessControlOperator(item.Target)
	}
	match := model.ProtectionRuleMatch{
		Target:     accessControlTarget(item.Target),
		Value:      item.Value,
		Operator:   operator,
		HeaderName: item.HeaderName,
		Methods:    []string{},
	}
	switch item.Target {
	case "uri":
		match.Target = "path"
		match.Path = item.Value
		match.PathMatch = operator
	case "host":
		match.Target = "host"
		match.Host = item.Value
	}
	return match
}

func accessControlTarget(target string) string {
	if target == "uri" {
		return "path"
	}
	return target
}

func defaultAccessControlOperator(target string) string {
	switch target {
	case "uri", "header", "host":
		return "exact"
	default:
		return ""
	}
}

func accessControlAction(item model.AccessListEntry) string {
	if item.Action == "allow" || item.Kind == "whitelist" {
		return "allow"
	}
	if item.Action == "log-only" {
		return "log-only"
	}
	return "block"
}

func accessControlActionFromRule(action string) string {
	switch action {
	case "allow":
		return "allow"
	case "log-only":
		return "log-only"
	default:
		return "block"
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

func ccRateLimitScope(counter string) string {
	switch counter {
	case "client_ip":
		return "ip"
	case "client_ip_path":
		return "uri"
	case "global":
		return "site"
	default:
		return "ip"
	}
}

func ccRateLimitMatchValue(match model.ProtectionRuleMatch) string {
	if match.Path == "/" {
		return ""
	}
	return match.Path
}

func ccRateLimitLegacyAction(action string) string {
	if action == "log-only" {
		return "log-only"
	}
	return "block"
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

func normalizeHTTPMethods(methods []string) []string {
	out := make([]string, 0, len(methods))
	seen := map[string]bool{}
	for _, method := range methods {
		item := strings.ToUpper(strings.TrimSpace(method))
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func normalizeExtensions(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		item := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "."))
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func priority(value int) int {
	if value <= 0 {
		return 100
	}
	return value
}

func cloneStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func oneOf(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}
