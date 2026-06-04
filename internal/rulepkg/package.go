package rulepkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/model"
	"litewaf-api/internal/store"
)

const (
	Compatibility = "litewaf-rule-package-v1"

	SignatureVerified     = "verified"
	SignatureUnsigned     = "unsigned"
	SignatureInvalid      = "invalid"
	SignatureUntrustedKey = "untrusted-key"

	ReviewPending  = "pending-review"
	ReviewApproved = "approved"

	TestPassed = "passed"
	TestFailed = "failed"
)

var trustedKeyIDs = map[string]bool{
	"litewaf-local":   true,
	"litewaf-default": true,
}

type rawPackage struct {
	ID            string                     `json:"id"`
	Name          string                     `json:"name"`
	Version       string                     `json:"version"`
	Author        string                     `json:"author"`
	License       string                     `json:"license"`
	Compatibility string                     `json:"compatibility"`
	Checksum      string                     `json:"checksum"`
	Signature     model.RulePackageSignature `json:"signature"`
	Defaults      model.RulePackageDefaults  `json:"defaults"`
	Rules         []rawRule                  `json:"rules"`
}

type rawRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Target     string `json:"target"`
	Action     string `json:"action"`
	Expression string `json:"expression"`
	Score      int    `json:"score"`
	Enabled    *bool  `json:"enabled"`
	Module     string `json:"module"`
	Category   string `json:"category"`
	AttackType string `json:"attack_type"`
	Group      string `json:"group"`
	Priority   int    `json:"priority"`
}

func Parse(data []byte) (model.RulePackage, []model.RulePackageError) {
	var input rawPackage
	if err := json.Unmarshal(data, &input); err != nil {
		return model.RulePackage{}, []model.RulePackageError{{Message: "package json is invalid"}}
	}
	pkg := model.RulePackage{
		Metadata: model.RulePackageMetadata{
			ID:            normalizeID(input.ID),
			Name:          strings.TrimSpace(input.Name),
			Version:       strings.TrimSpace(input.Version),
			Author:        strings.TrimSpace(input.Author),
			License:       strings.TrimSpace(input.License),
			Compatibility: strings.TrimSpace(input.Compatibility),
			Checksum:      strings.ToLower(strings.TrimSpace(input.Checksum)),
			Signature:     input.Signature,
			RuleCount:     len(input.Rules),
			Warnings:      []string{},
		},
		Defaults: input.Defaults,
		Rules:    []model.Rule{},
	}
	if pkg.Defaults.ReviewStatus == "" {
		pkg.Defaults.ReviewStatus = ReviewPending
	}
	if pkg.Metadata.Compatibility == "" {
		pkg.Metadata.Compatibility = Compatibility
	}

	errors := validateMetadata(pkg.Metadata)
	seen := map[string]bool{}
	for _, raw := range input.Rules {
		ruleID := normalizeID(raw.ID)
		if ruleID == "" {
			errors = append(errors, model.RulePackageError{Message: "rule id is required"})
			continue
		}
		if seen[ruleID] {
			errors = append(errors, model.RulePackageError{RuleID: ruleID, Message: "duplicate rule id"})
			continue
		}
		seen[ruleID] = true
		enabled := pkg.Defaults.Enabled
		if raw.Enabled != nil {
			enabled = *raw.Enabled
		}
		rule := model.Rule{
			Name:            strings.TrimSpace(raw.Name),
			Type:            strings.ToLower(strings.TrimSpace(raw.Type)),
			Target:          strings.ToLower(strings.TrimSpace(raw.Target)),
			Action:          strings.ToLower(strings.TrimSpace(raw.Action)),
			Expression:      strings.TrimSpace(raw.Expression),
			Score:           raw.Score,
			Enabled:         enabled,
			Module:          strings.TrimSpace(raw.Module),
			Category:        strings.TrimSpace(raw.Category),
			AttackType:      strings.TrimSpace(raw.AttackType),
			Group:           strings.TrimSpace(raw.Group),
			Priority:        raw.Priority,
			PackageID:       pkg.Metadata.ID,
			PackageVersion:  pkg.Metadata.Version,
			PackageRuleID:   ruleID,
			SourceChecksum:  checksumRule(raw),
			SignatureStatus: pkg.Metadata.SignatureStatus,
			ReviewStatus:    pkg.Defaults.ReviewStatus,
			LastTestStatus:  "",
		}
		if rule.Action == "" {
			rule.Action = "block"
		}
		if rule.Target == "" {
			rule.Target = "args"
		}
		if rule.Priority == 0 {
			rule.Priority = 100
		}
		rule = attackmeta.NormalizeRule(rule)
		if err := ValidateRule(rule); err != nil {
			errors = append(errors, model.RulePackageError{RuleID: ruleID, Message: err.Error()})
			continue
		}
		pkg.Rules = append(pkg.Rules, rule)
	}
	pkg.Metadata.RuleCount = len(pkg.Rules)
	pkg.Metadata.SignatureStatus = signatureStatus(pkg.Metadata)
	pkg.Metadata.Warnings = signatureWarnings(pkg.Metadata)
	return pkg, errors
}

func Preview(ctx context.Context, dataStore store.Store, data []byte) (model.RulePackagePreview, error) {
	return PreviewWithTrustKeys(ctx, dataStore, data, nil)
}

func PreviewWithTrustKeys(ctx context.Context, dataStore store.Store, data []byte, trustKeys []model.RuleTrustKey) (model.RulePackagePreview, error) {
	pkg, invalid := Parse(data)
	pkg = ApplyTrustKeys(pkg, trustKeys)
	if len(validateMetadata(pkg.Metadata)) > 0 {
		return model.RulePackagePreview{}, errors.New("rule package metadata is invalid")
	}
	existing, err := dataStore.ListRules(ctx)
	if err != nil {
		return model.RulePackagePreview{}, err
	}
	byOrigin := rulesByOrigin(existing)
	preview := model.RulePackagePreview{
		Package:      pkg.Metadata,
		Added:        []model.Rule{},
		Changed:      []model.Rule{},
		Skipped:      []model.Rule{},
		Invalid:      invalid,
		DefaultState: pkg.Defaults.Enabled,
		Warnings:     append([]string{}, pkg.Metadata.Warnings...),
	}
	for _, rule := range pkg.Rules {
		key := originKey(rule.PackageID, rule.PackageRuleID)
		current, ok := byOrigin[key]
		switch {
		case !ok:
			preview.Added = append(preview.Added, rule)
		case current.SourceChecksum != rule.SourceChecksum || current.PackageVersion != rule.PackageVersion:
			rule.ID = current.ID
			preview.Changed = append(preview.Changed, rule)
		default:
			rule.ID = current.ID
			preview.Skipped = append(preview.Skipped, rule)
		}
	}
	if pkg.Metadata.SignatureStatus != SignatureVerified {
		preview.Warnings = append(preview.Warnings, fmt.Sprintf("package signature status is %s", pkg.Metadata.SignatureStatus))
	}
	return preview, nil
}

func Import(ctx context.Context, dataStore store.Store, data []byte) (model.RulePackageImportResult, error) {
	return ImportWithTrustKeys(ctx, dataStore, data, nil)
}

func ImportWithTrustKeys(ctx context.Context, dataStore store.Store, data []byte, trustKeys []model.RuleTrustKey) (model.RulePackageImportResult, error) {
	preview, err := PreviewWithTrustKeys(ctx, dataStore, data, trustKeys)
	if err != nil {
		return model.RulePackageImportResult{}, err
	}
	if len(preview.Invalid) > 0 {
		return model.RulePackageImportResult{}, errors.New("rule package contains invalid rules")
	}
	result := model.RulePackageImportResult{
		Package:  preview.Package,
		Imported: []model.Rule{},
		Changed:  []model.Rule{},
		Skipped:  preview.Skipped,
		Invalid:  preview.Invalid,
	}
	for _, rule := range preview.Added {
		created, err := dataStore.CreateRule(ctx, rule)
		if err != nil {
			return model.RulePackageImportResult{}, err
		}
		result.Imported = append(result.Imported, created)
	}
	for _, rule := range preview.Changed {
		updated, err := dataStore.UpdateRule(ctx, rule.ID, rule)
		if err != nil {
			return model.RulePackageImportResult{}, err
		}
		result.Changed = append(result.Changed, updated)
	}
	return result, nil
}

func ApplyTrustKeys(pkg model.RulePackage, trustKeys []model.RuleTrustKey) model.RulePackage {
	pkg.Metadata.SignatureStatus = SignatureStatus(pkg.Metadata.Signature, pkg.Metadata.Checksum, trustKeys)
	pkg.Metadata.Warnings = signatureWarnings(pkg.Metadata)
	for i := range pkg.Rules {
		pkg.Rules[i].SignatureStatus = pkg.Metadata.SignatureStatus
	}
	return pkg
}

func PackagesFromRules(rules []model.Rule) []model.RulePackageMetadata {
	type aggregate struct {
		meta model.RulePackageMetadata
	}
	items := map[string]*aggregate{}
	for _, rule := range rules {
		if rule.PackageID == "" {
			continue
		}
		key := rule.PackageID + "@" + rule.PackageVersion
		if items[key] == nil {
			items[key] = &aggregate{meta: model.RulePackageMetadata{
				ID:              rule.PackageID,
				Name:            rule.PackageID,
				Version:         rule.PackageVersion,
				Compatibility:   Compatibility,
				SignatureStatus: rule.SignatureStatus,
				RuleCount:       0,
				Warnings:        signatureWarnings(model.RulePackageMetadata{SignatureStatus: rule.SignatureStatus}),
				CreatedAt:       rule.CreatedAt,
				UpdatedAt:       rule.UpdatedAt,
			}}
		}
		items[key].meta.RuleCount++
		if rule.UpdatedAt.After(items[key].meta.UpdatedAt) {
			items[key].meta.UpdatedAt = rule.UpdatedAt
		}
	}
	out := make([]model.RulePackageMetadata, 0, len(items))
	for _, item := range items {
		out = append(out, item.meta)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == out[j].ID {
			return out[i].Version < out[j].Version
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func TestRule(rule model.Rule, sample model.RuleTestSample) (model.RuleTestResult, error) {
	if err := ValidateRule(rule); err != nil {
		return model.RuleTestResult{}, err
	}
	if err := ValidateSample(sample); err != nil {
		return model.RuleTestResult{}, err
	}
	values := sampleValues(rule.Target, sample)
	matched := false
	diagnostics := map[string]string{
		"target": rule.Target,
	}
	if rule.Target == "upload_size" {
		matched = sample.UploadSize >= atoi(rule.Expression)
	} else {
		re, err := regexp.Compile(rule.Expression)
		if err != nil {
			return model.RuleTestResult{}, err
		}
		for _, value := range values {
			if re.MatchString(value) {
				matched = true
				break
			}
		}
	}
	status := TestFailed
	if matched {
		status = TestPassed
	}
	return model.RuleTestResult{
		RuleID:          rule.ID,
		Matched:         matched,
		Target:          rule.Target,
		EvaluatedValues: values,
		Action:          rule.Action,
		Score:           rule.Score,
		Status:          status,
		Diagnostics:     diagnostics,
	}, nil
}

func ValidateRule(rule model.Rule) error {
	if rule.Name == "" {
		return errors.New("rule name is required")
	}
	if rule.PackageID != "" && rule.PackageRuleID == "" {
		return errors.New("package rule id is required")
	}
	if rule.PackageRuleID != "" && rule.PackageID == "" {
		return errors.New("package id is required")
	}
	if !oneOf(rule.Type, "sqli", "xss", "rce", "path-traversal", "cc", "bot", "custom") {
		return errors.New("rule type is unsupported")
	}
	if !oneOf(rule.Target, "args", "uri", "headers", "normalized_uri", "normalized_path", "normalized_args", "normalized_headers", "body", "body_json", "body_form", "upload_filename", "upload_extension", "upload_mime", "upload_size") {
		return errors.New("rule target is unsupported")
	}
	if !oneOf(rule.Action, "pass", "block", "log-only") {
		return errors.New("rule action is unsupported")
	}
	if rule.Expression == "" {
		return errors.New("rule expression is required")
	}
	if rule.Target == "upload_size" {
		if atoi(rule.Expression) < 0 {
			return errors.New("upload_size expression must be non-negative")
		}
	} else if _, err := regexp.Compile(rule.Expression); err != nil {
		return errors.New("rule expression is invalid")
	}
	if rule.Score < 0 || rule.Score > 1000 {
		return errors.New("rule score must be between 0 and 1000")
	}
	if rule.AttackType != "" && !attackmeta.ValidAttackType(rule.AttackType) {
		return errors.New("rule attack_type is unsupported")
	}
	return nil
}

func ValidateSample(sample model.RuleTestSample) error {
	if len(sample.Body) > 65536 {
		return errors.New("sample body is too large")
	}
	if len(sample.Path) > 4096 {
		return errors.New("sample path is too large")
	}
	if len(sample.Headers) > 50 || len(sample.Query) > 50 {
		return errors.New("sample has too many fields")
	}
	for key, value := range sample.Headers {
		if strings.EqualFold(key, "authorization") || strings.EqualFold(key, "cookie") {
			return errors.New("sensitive sample headers are not allowed")
		}
		if len(value) > 4096 {
			return errors.New("sample header value is too large")
		}
	}
	for _, value := range sample.Query {
		if len(value) > 4096 {
			return errors.New("sample query value is too large")
		}
	}
	return nil
}

func validateMetadata(meta model.RulePackageMetadata) []model.RulePackageError {
	var errors []model.RulePackageError
	if meta.ID == "" {
		errors = append(errors, model.RulePackageError{Message: "package id is required"})
	}
	if meta.Name == "" {
		errors = append(errors, model.RulePackageError{Message: "package name is required"})
	}
	if meta.Version == "" {
		errors = append(errors, model.RulePackageError{Message: "package version is required"})
	}
	if meta.Compatibility != Compatibility {
		errors = append(errors, model.RulePackageError{Message: "package compatibility is unsupported"})
	}
	return errors
}

func signatureStatus(meta model.RulePackageMetadata) string {
	return SignatureStatus(meta.Signature, meta.Checksum, nil)
}

func signatureWarnings(meta model.RulePackageMetadata) []string {
	status := meta.SignatureStatus
	if status == "" {
		status = signatureStatus(meta)
	}
	switch status {
	case SignatureVerified:
		return []string{}
	case SignatureUnsigned:
		return []string{"package is unsigned"}
	case SignatureInvalid:
		return []string{"package signature is invalid"}
	case SignatureUntrustedKey:
		return []string{"package signature key is not trusted"}
	case SignatureRevokedKey:
		return []string{"package signature key is revoked"}
	case SignatureExpired:
		return []string{"package signature or key is expired"}
	default:
		return []string{"package signature status is unknown"}
	}
}

func rulesByOrigin(rules []model.Rule) map[string]model.Rule {
	out := map[string]model.Rule{}
	for _, rule := range rules {
		if rule.PackageID == "" || rule.PackageRuleID == "" {
			continue
		}
		out[originKey(rule.PackageID, rule.PackageRuleID)] = rule
	}
	return out
}

func originKey(packageID string, ruleID string) string {
	return normalizeID(packageID) + "/" + normalizeID(ruleID)
}

func normalizeID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	return value
}

func checksumRule(rule rawRule) string {
	payload, _ := json.Marshal(rule)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func sampleValues(target string, sample model.RuleTestSample) []string {
	switch target {
	case "uri", "normalized_uri", "normalized_path":
		return []string{sample.Path}
	case "args", "normalized_args":
		values := make([]string, 0, len(sample.Query))
		for key, value := range sample.Query {
			values = append(values, key+"="+value)
		}
		sort.Strings(values)
		return values
	case "headers", "normalized_headers":
		values := make([]string, 0, len(sample.Headers))
		for key, value := range sample.Headers {
			values = append(values, key+": "+value)
		}
		sort.Strings(values)
		return values
	case "body", "body_json", "body_form":
		return []string{sample.Body}
	case "upload_filename":
		return []string{sample.UploadFilename}
	case "upload_extension":
		parts := strings.Split(sample.UploadFilename, ".")
		if len(parts) <= 1 {
			return []string{}
		}
		return []string{parts[len(parts)-1]}
	case "upload_mime":
		return []string{sample.UploadMIME}
	case "upload_size":
		return []string{fmt.Sprintf("%d", sample.UploadSize)}
	default:
		return []string{}
	}
}

func atoi(value string) int {
	value = strings.TrimSpace(value)
	var out int
	if _, err := fmt.Sscanf(value, "%d", &out); err != nil {
		return -1
	}
	return out
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func MarkTested(rule model.Rule, result model.RuleTestResult) model.Rule {
	rule.LastTestStatus = result.Status
	if rule.ReviewStatus == "" {
		rule.ReviewStatus = ReviewPending
	}
	rule.UpdatedAt = time.Now().UTC()
	return rule
}
