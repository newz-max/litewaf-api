package rulepkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"litewaf-api/internal/model"
	"litewaf-api/internal/store"
)

const (
	CatalogStatusNeverSynced = "never-synced"
	CatalogStatusSynced      = "synced"
	CatalogStatusFailed      = "failed"
	CatalogStatusDisabled    = "disabled"

	SignatureRevokedKey = "revoked-key"
	SignatureExpired    = "expired"

	UpdatePending = "pending"
	UpdateCurrent = "current"
	UpdateApplied = "applied"
)

type rawCatalog struct {
	SchemaVersion string              `json:"schema_version"`
	Packages      []rawCatalogPackage `json:"packages"`
}

type rawCatalogPackage struct {
	ID            string                     `json:"id"`
	Name          string                     `json:"name"`
	Version       string                     `json:"version"`
	Compatibility string                     `json:"compatibility"`
	Checksum      string                     `json:"checksum"`
	Signature     model.RulePackageSignature `json:"signature"`
	UpdatedAt     string                     `json:"updated_at"`
	ManifestURL   string                     `json:"manifest_url"`
	Package       json.RawMessage            `json:"package"`
}

func NormalizeCatalogSource(item model.RuleCatalogSource) model.RuleCatalogSource {
	item.Name = strings.TrimSpace(item.Name)
	item.Source = strings.TrimSpace(item.Source)
	if item.TimeoutSec <= 0 {
		item.TimeoutSec = 5
	}
	if item.TimeoutSec > 30 {
		item.TimeoutSec = 30
	}
	if item.Status == "" {
		item.Status = CatalogStatusNeverSynced
	}
	return item
}

func ValidateCatalogSource(item model.RuleCatalogSource) error {
	if strings.TrimSpace(item.Name) == "" {
		return errors.New("catalog name is required")
	}
	source := strings.TrimSpace(item.Source)
	if source == "" {
		return errors.New("catalog source is required")
	}
	if strings.HasPrefix(source, "http://") {
		return errors.New("catalog source must use https or local file path")
	}
	if strings.HasPrefix(source, "https://") {
		parsed, err := url.Parse(source)
		if err != nil || parsed.Host == "" {
			return errors.New("catalog source url is invalid")
		}
		return nil
	}
	if strings.Contains(source, "\x00") {
		return errors.New("catalog source path is invalid")
	}
	return nil
}

func ValidateTrustKey(item model.RuleTrustKey) error {
	if strings.TrimSpace(item.KeyID) == "" {
		return errors.New("trust key id is required")
	}
	if strings.TrimSpace(item.Algorithm) == "" {
		return errors.New("trust key algorithm is required")
	}
	if !oneOf(strings.ToLower(strings.TrimSpace(item.Algorithm)), "ed25519", "rsa", "ecdsa", "local") {
		return errors.New("trust key algorithm is unsupported")
	}
	return nil
}

func SyncCatalog(ctx context.Context, dataStore store.Store, source model.RuleCatalogSource) ([]model.RuleCatalogPackage, error) {
	trustKeys, _ := dataStore.ListRuleTrustKeys(ctx)
	return SyncCatalogWithTrustKeys(ctx, dataStore, source, trustKeys)
}

func SyncCatalogWithTrustKeys(ctx context.Context, dataStore store.Store, source model.RuleCatalogSource, trustKeys []model.RuleTrustKey) ([]model.RuleCatalogPackage, error) {
	source = NormalizeCatalogSource(source)
	if !source.Enabled {
		source.Status = CatalogStatusDisabled
		_, _ = dataStore.UpdateRuleCatalogSource(ctx, source.ID, source)
		return []model.RuleCatalogPackage{}, nil
	}
	if err := ValidateCatalogSource(source); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(source.TimeoutSec)*time.Second)
	defer cancel()
	data, err := readCatalog(ctx, source.Source)
	if err != nil {
		source.Status = CatalogStatusFailed
		source.LastError = err.Error()
		_, _ = dataStore.UpdateRuleCatalogSource(context.Background(), source.ID, source)
		return nil, err
	}
	items, err := ParseCatalogWithTrustKeys(data, source, trustKeys)
	if err != nil {
		source.Status = CatalogStatusFailed
		source.LastError = err.Error()
		_, _ = dataStore.UpdateRuleCatalogSource(context.Background(), source.ID, source)
		return nil, err
	}
	if err := dataStore.ReplaceRuleCatalogPackages(ctx, source.ID, items); err != nil {
		return nil, err
	}
	return items, nil
}

func ParseCatalog(data []byte, source model.RuleCatalogSource) ([]model.RuleCatalogPackage, error) {
	return ParseCatalogWithTrustKeys(data, source, nil)
}

func ParseCatalogWithTrustKeys(data []byte, source model.RuleCatalogSource, trustKeys []model.RuleTrustKey) ([]model.RuleCatalogPackage, error) {
	var input rawCatalog
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, errors.New("catalog json is invalid")
	}
	if input.SchemaVersion != "" && input.SchemaVersion != "litewaf-rule-catalog-v1" {
		return nil, errors.New("catalog schema version is unsupported")
	}
	now := time.Now().UTC()
	items := make([]model.RuleCatalogPackage, 0, len(input.Packages))
	seen := map[string]bool{}
	for _, raw := range input.Packages {
		packageID := normalizeID(raw.ID)
		if packageID == "" {
			return nil, errors.New("catalog package id is required")
		}
		if seen[packageID] {
			return nil, fmt.Errorf("duplicate catalog package id %s", packageID)
		}
		seen[packageID] = true
		packageJSON := strings.TrimSpace(string(raw.Package))
		item := model.RuleCatalogPackage{
			CatalogID:       source.ID,
			PackageID:       packageID,
			Name:            strings.TrimSpace(raw.Name),
			Version:         strings.TrimSpace(raw.Version),
			Compatibility:   strings.TrimSpace(raw.Compatibility),
			Checksum:        strings.ToLower(strings.TrimSpace(raw.Checksum)),
			Signature:       raw.Signature,
			SignatureStatus: SignatureUnsigned,
			UpdatedAtText:   strings.TrimSpace(raw.UpdatedAt),
			ManifestURL:     strings.TrimSpace(raw.ManifestURL),
			PackageJSON:     packageJSON,
			SourceIdentity:  source.Source,
			SyncStatus:      CatalogStatusSynced,
			LastSyncedAt:    now,
		}
		if item.Name == "" {
			item.Name = packageID
		}
		if item.Version == "" {
			return nil, fmt.Errorf("catalog package %s version is required", packageID)
		}
		if item.Compatibility == "" {
			item.Compatibility = Compatibility
		}
		if item.Compatibility != Compatibility {
			return nil, fmt.Errorf("catalog package %s compatibility is unsupported", packageID)
		}
		if item.PackageJSON != "" {
			sum := checksumBytes([]byte(item.PackageJSON))
			if item.Checksum == "" {
				item.Checksum = sum
			} else if !strings.EqualFold(item.Checksum, sum) {
				return nil, fmt.Errorf("catalog package %s checksum mismatch", packageID)
			}
		}
		item.SignatureStatus = SignatureStatus(item.Signature, item.Checksum, trustKeys)
		items = append(items, item)
	}
	return items, nil
}

func RemotePreview(ctx context.Context, dataStore store.Store, catalogPackage model.RuleCatalogPackage) (model.RulePackagePreview, error) {
	trustKeys, _ := dataStore.ListRuleTrustKeys(ctx)
	return RemotePreviewWithTrustKeys(ctx, dataStore, catalogPackage, trustKeys)
}

func RemotePreviewWithTrustKeys(ctx context.Context, dataStore store.Store, catalogPackage model.RuleCatalogPackage, trustKeys []model.RuleTrustKey) (model.RulePackagePreview, error) {
	data, err := CatalogPackageData(ctx, catalogPackage)
	if err != nil {
		return model.RulePackagePreview{}, err
	}
	if catalogPackage.Checksum != "" && !strings.EqualFold(catalogPackage.Checksum, checksumBytes(data)) {
		return model.RulePackagePreview{}, errors.New("remote package checksum mismatch")
	}
	preview, err := PreviewWithTrustKeys(ctx, dataStore, data, trustKeys)
	if err != nil {
		return model.RulePackagePreview{}, err
	}
	preview.SourceCatalogID = fmt.Sprintf("%d", catalogPackage.CatalogID)
	preview.CompatibilityStatus = "compatible"
	if preview.Package.Compatibility != Compatibility {
		preview.CompatibilityStatus = "incompatible"
		return preview, errors.New("remote package compatibility is unsupported")
	}
	return preview, nil
}

func CatalogPackageData(ctx context.Context, catalogPackage model.RuleCatalogPackage) ([]byte, error) {
	if strings.TrimSpace(catalogPackage.PackageJSON) != "" {
		return []byte(catalogPackage.PackageJSON), nil
	}
	if strings.TrimSpace(catalogPackage.ManifestURL) == "" {
		return nil, errors.New("catalog package manifest is missing")
	}
	return readCatalog(ctx, catalogPackage.ManifestURL)
}

func UpdatePreview(ctx context.Context, dataStore store.Store, catalogPackage model.RuleCatalogPackage) (model.RulePackageUpdatePreview, error) {
	trustKeys, _ := dataStore.ListRuleTrustKeys(ctx)
	return UpdatePreviewWithTrustKeys(ctx, dataStore, catalogPackage, trustKeys)
}

func UpdatePreviewWithTrustKeys(ctx context.Context, dataStore store.Store, catalogPackage model.RuleCatalogPackage, trustKeys []model.RuleTrustKey) (model.RulePackageUpdatePreview, error) {
	preview, err := RemotePreviewWithTrustKeys(ctx, dataStore, catalogPackage, trustKeys)
	if err != nil {
		return model.RulePackageUpdatePreview{}, err
	}
	rules, err := dataStore.ListRules(ctx)
	if err != nil {
		return model.RulePackageUpdatePreview{}, err
	}
	currentVersion := ""
	currentChecksum := ""
	removed := []model.Rule{}
	unchanged := []model.Rule{}
	candidateIDs := map[string]bool{}
	for _, rule := range preview.Added {
		candidateIDs[rule.PackageRuleID] = true
	}
	for _, rule := range preview.Changed {
		candidateIDs[rule.PackageRuleID] = true
	}
	for _, rule := range preview.Skipped {
		candidateIDs[rule.PackageRuleID] = true
		unchanged = append(unchanged, rule)
	}
	for _, rule := range rules {
		if rule.PackageID != catalogPackage.PackageID {
			continue
		}
		if currentVersion == "" {
			currentVersion = rule.PackageVersion
			currentChecksum = rule.SourceChecksum
		}
		if !candidateIDs[rule.PackageRuleID] {
			removed = append(removed, rule)
		}
	}
	return model.RulePackageUpdatePreview{
		Package:           preview.Package,
		CurrentVersion:    currentVersion,
		CandidateVersion:  catalogPackage.Version,
		CurrentChecksum:   currentChecksum,
		CandidateChecksum: catalogPackage.Checksum,
		SourceCatalogID:   catalogPackage.CatalogID,
		Added:             preview.Added,
		Changed:           preview.Changed,
		Removed:           removed,
		Unchanged:         unchanged,
		Skipped:           preview.Skipped,
		Invalid:           preview.Invalid,
		Warnings:          preview.Warnings,
		SignatureStatus:   preview.Package.SignatureStatus,
	}, nil
}

func ApplyUpdate(ctx context.Context, dataStore store.Store, catalogPackage model.RuleCatalogPackage) (model.RulePackageImportResult, error) {
	trustKeys, _ := dataStore.ListRuleTrustKeys(ctx)
	return ApplyUpdateWithTrustKeys(ctx, dataStore, catalogPackage, trustKeys)
}

func ApplyUpdateWithTrustKeys(ctx context.Context, dataStore store.Store, catalogPackage model.RuleCatalogPackage, trustKeys []model.RuleTrustKey) (model.RulePackageImportResult, error) {
	data, err := CatalogPackageData(ctx, catalogPackage)
	if err != nil {
		return model.RulePackageImportResult{}, err
	}
	result, err := ImportWithTrustKeys(ctx, dataStore, data, trustKeys)
	if err != nil {
		return result, err
	}
	for _, rule := range append(result.Imported, result.Changed...) {
		rule.RemoteCatalogID = fmt.Sprintf("%d", catalogPackage.CatalogID)
		rule.LastSyncedVersion = catalogPackage.Version
		rule.PendingUpdateState = UpdateApplied
		if rule.LocalOverrideState == "" {
			rule.LocalOverrideState = "none"
		}
		_, _ = dataStore.UpdateRule(ctx, rule.ID, rule)
	}
	return result, nil
}

func ExportPreview(ctx context.Context, dataStore store.Store, req model.RulePackageExportRequest) (model.RulePackageExportPreview, error) {
	req = normalizeExportRequest(req)
	if err := validateExportRequest(req); err != nil {
		return model.RulePackageExportPreview{}, err
	}
	rules, err := dataStore.ListRules(ctx)
	if err != nil {
		return model.RulePackageExportPreview{}, err
	}
	byID := map[int64]model.Rule{}
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	selected := []model.Rule{}
	invalid := []model.RulePackageError{}
	seenRuleIDs := map[string]bool{}
	for _, id := range req.RuleIDs {
		rule, ok := byID[id]
		if !ok {
			invalid = append(invalid, model.RulePackageError{Message: fmt.Sprintf("rule %d not found", id)})
			continue
		}
		exportRuleID := exportRuleID(rule)
		if seenRuleIDs[exportRuleID] {
			invalid = append(invalid, model.RulePackageError{RuleID: exportRuleID, Message: "duplicate package rule id"})
			continue
		}
		seenRuleIDs[exportRuleID] = true
		if err := ValidateRule(rule); err != nil {
			invalid = append(invalid, model.RulePackageError{RuleID: exportRuleID, Message: err.Error()})
			continue
		}
		rule.ExportEligible = true
		rule.ExportIneligibleReasons = []string{}
		selected = append(selected, rule)
	}
	meta := model.RulePackageMetadata{
		ID:            req.PackageID,
		Name:          req.Name,
		Version:       req.Version,
		Author:        req.Author,
		License:       req.License,
		Compatibility: req.Compatibility,
		RuleCount:     len(selected),
	}
	warnings := []string{}
	signingStatus := SignatureUnsigned
	if req.SigningKeyID != "" {
		signingStatus = "signing-metadata"
		meta.Signature.KeyID = req.SigningKeyID
		warnings = append(warnings, "export includes signing metadata only; sign artifact with your private key outside LiteWaf")
	}
	return model.RulePackageExportPreview{
		Package:       meta,
		SelectedRules: selected,
		Invalid:       invalid,
		Warnings:      warnings,
		ChecksumPlan:  "sha256 over exported package json",
		SigningStatus: signingStatus,
	}, nil
}

func ExportArtifact(ctx context.Context, dataStore store.Store, req model.RulePackageExportRequest) (model.RulePackageExportArtifact, error) {
	preview, err := ExportPreview(ctx, dataStore, req)
	if err != nil {
		return model.RulePackageExportArtifact{}, err
	}
	if len(preview.Invalid) > 0 {
		return model.RulePackageExportArtifact{}, errors.New("export contains invalid rules")
	}
	payload := map[string]any{
		"id":            preview.Package.ID,
		"name":          preview.Package.Name,
		"version":       preview.Package.Version,
		"author":        preview.Package.Author,
		"license":       preview.Package.License,
		"compatibility": preview.Package.Compatibility,
		"defaults": map[string]any{
			"enabled":       false,
			"review_status": ReviewPending,
		},
		"rules": exportRules(preview.SelectedRules),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return model.RulePackageExportArtifact{}, err
	}
	checksum := checksumBytes(data)
	var envelope map[string]any
	if err := json.Unmarshal(data, &envelope); err != nil {
		return model.RulePackageExportArtifact{}, err
	}
	envelope["checksum"] = checksum
	if preview.Package.Signature.KeyID != "" {
		envelope["signature"] = map[string]string{
			"key_id":   preview.Package.Signature.KeyID,
			"checksum": checksum,
		}
	}
	finalData, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return model.RulePackageExportArtifact{}, err
	}
	return model.RulePackageExportArtifact{
		Package:   preview.Package,
		Artifact:  string(finalData),
		Checksum:  checksumBytes(finalData),
		RuleCount: len(preview.SelectedRules),
		Guidance: []string{
			"Review exported rules before publishing.",
			"Do not add private keys, API tokens, raw traffic samples, or deployment secrets.",
			"Submit the package artifact through the documented community review process.",
		},
		CreatedAt: time.Now().UTC(),
	}, nil
}

func SignatureStatus(signature model.RulePackageSignature, checksum string, trustKeys []model.RuleTrustKey) string {
	if signature.KeyID == "" && signature.Signature == "" {
		return SignatureUnsigned
	}
	if signature.Checksum != "" && checksum != "" && !strings.EqualFold(signature.Checksum, checksum) {
		return SignatureInvalid
	}
	if signature.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, signature.ExpiresAt)
		if err == nil && time.Now().UTC().After(expires) {
			return SignatureExpired
		}
	}
	if len(trustKeys) > 0 {
		key, ok := findTrustKey(signature.KeyID, trustKeys)
		if !ok || !key.Enabled {
			return SignatureUntrustedKey
		}
		if key.Revoked {
			return SignatureRevokedKey
		}
		if !key.ExpiresAt.IsZero() && time.Now().UTC().After(key.ExpiresAt) {
			return SignatureExpired
		}
	} else if !trustedKeyIDs[signature.KeyID] {
		return SignatureUntrustedKey
	}
	if signature.Signature != "" && checksum != "" && strings.EqualFold(signature.Signature, checksum) {
		return SignatureVerified
	}
	return SignatureInvalid
}

func EvaluateRuleExportEligibility(rule model.Rule) model.Rule {
	rule.ExportEligible = true
	rule.ExportIneligibleReasons = []string{}
	if err := ValidateRule(rule); err != nil {
		rule.ExportEligible = false
		rule.ExportIneligibleReasons = append(rule.ExportIneligibleReasons, err.Error())
	}
	if rule.Type == "" || rule.Target == "" || rule.Action == "" || rule.Expression == "" {
		rule.ExportEligible = false
		rule.ExportIneligibleReasons = append(rule.ExportIneligibleReasons, "rule is missing required export fields")
	}
	return rule
}

func readCatalog(ctx context.Context, source string) ([]byte, error) {
	if strings.HasPrefix(source, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("catalog request failed with status %d", resp.StatusCode)
		}
		return readLimited(resp.Body)
	}
	return os.ReadFile(source)
}

func readLimited(reader io.Reader) ([]byte, error) {
	const limit = 2 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("catalog response is too large")
	}
	return data, nil
}

func checksumBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func findTrustKey(keyID string, keys []model.RuleTrustKey) (model.RuleTrustKey, bool) {
	for _, key := range keys {
		if key.KeyID == keyID {
			return key, true
		}
	}
	return model.RuleTrustKey{}, false
}

func normalizeExportRequest(req model.RulePackageExportRequest) model.RulePackageExportRequest {
	req.PackageID = normalizeID(req.PackageID)
	req.Name = strings.TrimSpace(req.Name)
	req.Version = strings.TrimSpace(req.Version)
	req.Author = strings.TrimSpace(req.Author)
	req.License = strings.TrimSpace(req.License)
	req.Compatibility = strings.TrimSpace(req.Compatibility)
	if req.Compatibility == "" {
		req.Compatibility = Compatibility
	}
	sort.Slice(req.RuleIDs, func(i, j int) bool { return req.RuleIDs[i] < req.RuleIDs[j] })
	return req
}

func validateExportRequest(req model.RulePackageExportRequest) error {
	if req.PackageID == "" {
		return errors.New("export package id is required")
	}
	if req.Name == "" {
		return errors.New("export package name is required")
	}
	if req.Version == "" {
		return errors.New("export package version is required")
	}
	if req.Compatibility != Compatibility {
		return errors.New("export package compatibility is unsupported")
	}
	if len(req.RuleIDs) == 0 {
		return errors.New("export requires at least one rule")
	}
	return nil
}

func exportRuleID(rule model.Rule) string {
	if rule.PackageRuleID != "" {
		return normalizeID(rule.PackageRuleID)
	}
	return normalizeID(rule.Name)
}

func exportRules(rules []model.Rule) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"id":          exportRuleID(rule),
			"name":        rule.Name,
			"type":        rule.Type,
			"target":      rule.Target,
			"action":      rule.Action,
			"expression":  rule.Expression,
			"score":       rule.Score,
			"enabled":     false,
			"module":      rule.Module,
			"category":    rule.Category,
			"attack_type": rule.AttackType,
			"group":       rule.Group,
			"priority":    rule.Priority,
		})
	}
	return out
}
