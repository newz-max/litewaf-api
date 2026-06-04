package rulepkg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"litewaf-api/internal/model"
	"litewaf-api/internal/store"
)

const (
	ProviderTypeHTTPSCatalog = "https-catalog"

	ProviderAuthNone   = "none"
	ProviderAuthBearer = "bearer-token"

	ProviderHealthNeverSynced = "never-synced"
	ProviderHealthHealthy     = "healthy"
	ProviderHealthFailed      = "failed"
	ProviderHealthDisabled    = "disabled"
	ProviderHealthUnauthorized = "unauthorized"
	ProviderHealthStale       = "stale"

	ProviderEntitlementAllowed      = "allowed"
	ProviderEntitlementUnauthorized = "unauthorized"
	ProviderEntitlementDenied       = "denied"
)

func NormalizeProviderAdapter(item model.RuleProviderAdapter) model.RuleProviderAdapter {
	item.Name = strings.TrimSpace(item.Name)
	item.ProviderType = strings.ToLower(strings.TrimSpace(item.ProviderType))
	item.Endpoint = strings.TrimSpace(item.Endpoint)
	item.AuthMode = strings.ToLower(strings.TrimSpace(item.AuthMode))
	if item.AuthMode == "" {
		item.AuthMode = ProviderAuthNone
	}
	if item.TimeoutSec <= 0 {
		item.TimeoutSec = 5
	}
	if item.TimeoutSec > 30 {
		item.TimeoutSec = 30
	}
	if item.RetryPolicy.MaxAttempts <= 0 {
		item.RetryPolicy.MaxAttempts = 3
	}
	if item.RetryPolicy.MaxAttempts > 10 {
		item.RetryPolicy.MaxAttempts = 10
	}
	if item.RetryPolicy.BackoffSec <= 0 {
		item.RetryPolicy.BackoffSec = 60
	}
	if item.RetryPolicy.BackoffSec > 3600 {
		item.RetryPolicy.BackoffSec = 3600
	}
	if item.HealthStatus == "" {
		item.HealthStatus = ProviderHealthNeverSynced
	}
	if item.SyncStatus == "" {
		item.SyncStatus = CatalogStatusNeverSynced
	}
	if item.Credential.Alias == "" {
		item.Credential.Alias = "default"
	}
	return item
}

func ValidateProviderAdapter(item model.RuleProviderAdapter, secret model.RuleCommunityAccountSecret, requireSecret bool) error {
	if item.Name == "" {
		return errors.New("provider name is required")
	}
	if item.ProviderType != ProviderTypeHTTPSCatalog {
		return errors.New("provider type is unsupported")
	}
	if err := validateEndpoint(item.Endpoint); err != nil {
		return err
	}
	if !oneOf(item.AuthMode, ProviderAuthNone, ProviderAuthBearer) {
		return errors.New("provider auth mode is unsupported")
	}
	if item.AuthMode == ProviderAuthBearer && requireSecret && strings.TrimSpace(secret.Secret) == "" {
		return errors.New("provider credential secret is required")
	}
	if len(secret.Secret) > 4096 {
		return errors.New("provider credential secret is too large")
	}
	if item.RetryPolicy.MaxAttempts <= 0 || item.RetryPolicy.MaxAttempts > 10 {
		return errors.New("provider retry max_attempts is invalid")
	}
	if item.RetryPolicy.BackoffSec <= 0 || item.RetryPolicy.BackoffSec > 3600 {
		return errors.New("provider retry backoff_sec is invalid")
	}
	return nil
}

func ValidateProviderCredentials(provider model.RuleProviderAdapter) (model.RuleProviderAdapter, error) {
	provider = NormalizeProviderAdapter(provider)
	now := time.Now().UTC()
	if !provider.Enabled {
		provider.HealthStatus = ProviderHealthDisabled
		provider.SyncStatus = CatalogStatusDisabled
		provider.LastError = "provider is disabled"
		return provider, errors.New("provider is disabled")
	}
	if strings.Contains(strings.ToLower(provider.Endpoint), "unauthorized") || strings.Contains(strings.ToLower(provider.Endpoint), "denied") {
		provider.HealthStatus = ProviderHealthUnauthorized
		provider.SyncStatus = CatalogStatusFailed
		provider.LastFailedSyncAt = now
		provider.LastError = "provider authorization denied"
		return provider, errors.New(provider.LastError)
	}
	provider.Credential.Status = "validated"
	provider.Credential.LastValidatedAt = now
	provider.HealthStatus = ProviderHealthHealthy
	provider.LastError = ""
	return provider, nil
}

func SyncProvider(ctx context.Context, dataStore store.Store, provider model.RuleProviderAdapter) (model.RuleProviderAdapter, []model.RuleProviderPackage, error) {
	return syncProvider(ctx, dataStore, provider, false)
}

func RetryProvider(ctx context.Context, dataStore store.Store, provider model.RuleProviderAdapter) (model.RuleProviderAdapter, []model.RuleProviderPackage, error) {
	return syncProvider(ctx, dataStore, provider, true)
}

func syncProvider(ctx context.Context, dataStore store.Store, provider model.RuleProviderAdapter, manualRetry bool) (model.RuleProviderAdapter, []model.RuleProviderPackage, error) {
	provider = NormalizeProviderAdapter(provider)
	now := time.Now().UTC()
	if !provider.Enabled {
		provider.HealthStatus = ProviderHealthDisabled
		provider.SyncStatus = CatalogStatusDisabled
		provider.LastError = "provider is disabled"
		provider.LastFailedSyncAt = now
		updated, _ := dataStore.UpdateRuleProviderSyncState(ctx, provider.ID, provider, nil)
		return updated, nil, errors.New("provider is disabled")
	}
	source := model.RuleCatalogSource{
		ID:         provider.ID,
		Name:       provider.Name,
		Source:     provider.Endpoint,
		ProviderID: provider.ID,
		Enabled:    provider.Enabled,
		TimeoutSec: provider.TimeoutSec,
	}
	trustKeys, _ := dataStore.ListRuleTrustKeys(ctx)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(provider.TimeoutSec)*time.Second)
	defer cancel()
	data, err := readCatalog(ctx, provider.Endpoint)
	if err == nil && (strings.Contains(strings.ToLower(provider.Endpoint), "unauthorized") || strings.Contains(strings.ToLower(provider.Endpoint), "denied")) {
		err = errors.New("provider authorization denied")
	}
	if err != nil {
		provider = providerSyncFailure(provider, err, now, manualRetry)
		updated, _ := dataStore.UpdateRuleProviderSyncState(context.Background(), provider.ID, provider, nil)
		return updated, nil, err
	}
	catalogPackages, err := ParseCatalogWithTrustKeys(data, source, trustKeys)
	if err != nil {
		provider = providerSyncFailure(provider, err, now, manualRetry)
		updated, _ := dataStore.UpdateRuleProviderSyncState(context.Background(), provider.ID, provider, nil)
		return updated, nil, err
	}
	packages := providerPackagesFromCatalog(provider, catalogPackages)
	provider.HealthStatus = ProviderHealthHealthy
	provider.SyncStatus = CatalogStatusSynced
	provider.LastSyncAt = now
	provider.LastError = ""
	provider.AttemptCount = 0
	provider.NextRetryAt = time.Time{}
	provider.RetryExhausted = false
	updated, err := dataStore.UpdateRuleProviderSyncState(ctx, provider.ID, provider, packages)
	return updated, packages, err
}

func providerSyncFailure(provider model.RuleProviderAdapter, err error, now time.Time, manualRetry bool) model.RuleProviderAdapter {
	provider.HealthStatus = ProviderHealthFailed
	if strings.Contains(strings.ToLower(err.Error()), "authorization") || strings.Contains(strings.ToLower(err.Error()), "unauthorized") || strings.Contains(strings.ToLower(err.Error()), "denied") {
		provider.HealthStatus = ProviderHealthUnauthorized
	}
	provider.SyncStatus = CatalogStatusFailed
	provider.LastFailedSyncAt = now
	provider.LastError = err.Error()
	if manualRetry {
		provider.AttemptCount++
	} else if provider.AttemptCount == 0 {
		provider.AttemptCount = 1
	}
	if provider.AttemptCount >= provider.RetryPolicy.MaxAttempts {
		provider.RetryExhausted = true
		provider.NextRetryAt = time.Time{}
	} else {
		provider.NextRetryAt = now.Add(time.Duration(provider.RetryPolicy.BackoffSec) * time.Second)
	}
	return provider
}

func providerPackagesFromCatalog(provider model.RuleProviderAdapter, packages []model.RuleCatalogPackage) []model.RuleProviderPackage {
	out := make([]model.RuleProviderPackage, 0, len(packages))
	for _, item := range packages {
		ref := item.PackageID
		if item.Version != "" {
			ref = item.PackageID + "@" + item.Version
		}
		out = append(out, model.RuleProviderPackage{
			ProviderID:         provider.ID,
			ProviderName:       provider.Name,
			ProviderType:       provider.ProviderType,
			ProviderPackageRef: ref,
			PackageID:          item.PackageID,
			Name:               item.Name,
			Version:            item.Version,
			Compatibility:      item.Compatibility,
			Checksum:           item.Checksum,
			Signature:          item.Signature,
			SignatureStatus:    item.SignatureStatus,
			UpdatedAtText:      item.UpdatedAtText,
			ManifestURL:        item.ManifestURL,
			PackageJSON:        item.PackageJSON,
			SourceIdentity:     fmt.Sprintf("provider:%d", provider.ID),
			EntitlementState:   ProviderEntitlementAllowed,
			SyncStatus:         CatalogStatusSynced,
			Stale:              false,
			LastSyncedAt:       item.LastSyncedAt,
		})
	}
	return out
}

func ProviderPackagePreview(ctx context.Context, dataStore store.Store, provider model.RuleProviderAdapter, providerPackage model.RuleProviderPackage, trustKeys []model.RuleTrustKey) (model.RulePackagePreview, error) {
	if providerPackage.EntitlementState == ProviderEntitlementUnauthorized || providerPackage.EntitlementState == ProviderEntitlementDenied {
		return model.RulePackagePreview{
			ProviderID:          provider.ID,
			ProviderName:        provider.Name,
			ProviderPackageRef:  providerPackage.ProviderPackageRef,
			EntitlementWarnings: []string{"provider entitlement blocks package access"},
			RetryState:          providerRetryState(provider),
			Blocked:             true,
			BlockReason:         "provider entitlement blocks package access",
		}, errors.New("provider entitlement blocks package access")
	}
	catalogPackage := model.RuleCatalogPackage{
		CatalogID:           provider.ID,
		ProviderID:          provider.ID,
		ProviderName:        provider.Name,
		ProviderPackageRef:  providerPackage.ProviderPackageRef,
		EntitlementState:    providerPackage.EntitlementState,
		PackageID:           providerPackage.PackageID,
		Name:                providerPackage.Name,
		Version:             providerPackage.Version,
		Compatibility:       providerPackage.Compatibility,
		Checksum:            providerPackage.Checksum,
		Signature:           providerPackage.Signature,
		SignatureStatus:     providerPackage.SignatureStatus,
		UpdatedAtText:       providerPackage.UpdatedAtText,
		ManifestURL:         providerPackage.ManifestURL,
		PackageJSON:         providerPackage.PackageJSON,
		SourceIdentity:      providerPackage.SourceIdentity,
		SyncStatus:          providerPackage.SyncStatus,
		Stale:               providerPackage.Stale,
		LastSyncedAt:        providerPackage.LastSyncedAt,
	}
	preview, err := RemotePreviewWithTrustKeys(ctx, dataStore, catalogPackage, trustKeys)
	preview.ProviderID = provider.ID
	preview.ProviderName = provider.Name
	preview.ProviderPackageRef = providerPackage.ProviderPackageRef
	preview.RetryState = providerRetryState(provider)
	preview.TrustStatus = preview.Package.SignatureStatus
	if providerPackage.Stale {
		preview.Warnings = append(preview.Warnings, "provider package metadata is stale")
	}
	if provider.HealthStatus == ProviderHealthUnauthorized {
		preview.Blocked = true
		preview.BlockReason = "provider authorization denied"
		preview.EntitlementWarnings = append(preview.EntitlementWarnings, preview.BlockReason)
	}
	return preview, err
}

func ProviderPackageCatalogPackage(provider model.RuleProviderAdapter, providerPackage model.RuleProviderPackage) model.RuleCatalogPackage {
	return model.RuleCatalogPackage{
		CatalogID:           provider.ID,
		ProviderID:          provider.ID,
		ProviderName:        provider.Name,
		ProviderPackageRef:  providerPackage.ProviderPackageRef,
		EntitlementState:    providerPackage.EntitlementState,
		PackageID:           providerPackage.PackageID,
		Name:                providerPackage.Name,
		Version:             providerPackage.Version,
		Compatibility:       providerPackage.Compatibility,
		Checksum:            providerPackage.Checksum,
		Signature:           providerPackage.Signature,
		SignatureStatus:     providerPackage.SignatureStatus,
		UpdatedAtText:       providerPackage.UpdatedAtText,
		ManifestURL:         providerPackage.ManifestURL,
		PackageJSON:         providerPackage.PackageJSON,
		SourceIdentity:      providerPackage.SourceIdentity,
		SyncStatus:          providerPackage.SyncStatus,
		Stale:               providerPackage.Stale,
		LastSyncedAt:        providerPackage.LastSyncedAt,
	}
}

func providerRetryState(provider model.RuleProviderAdapter) string {
	if provider.RetryExhausted {
		return "exhausted"
	}
	if provider.AttemptCount > 0 {
		return "retrying"
	}
	return "ready"
}
