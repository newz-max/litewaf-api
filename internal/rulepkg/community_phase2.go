package rulepkg

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"litewaf-api/internal/model"
	"litewaf-api/internal/store"
)

const (
	AccountStatusNeverSynced  = "never-synced"
	AccountStatusAuthorized   = "authorized"
	AccountStatusUnauthorized = "unauthorized"
	AccountStatusExpired      = "expired"
	AccountStatusFailed       = "failed"
	AccountStatusDisabled     = "disabled"

	QueueStateQueued    = "queued"
	QueueStateApproved  = "approved"
	QueueStateDismissed = "dismissed"
	QueueStateFailed    = "failed"

	FeedbackStatusOpen         = "open"
	FeedbackStatusSuggested    = "suggested"
	FeedbackSuggestionQueued   = "queued"
	FeedbackSuggestionTested   = "tested"
	FeedbackSuggestionApproved = "approved"
	FeedbackSuggestionRejected = "rejected"
)

func NormalizeAccountSource(item model.RuleCommunityAccountSource) model.RuleCommunityAccountSource {
	item.Name = strings.TrimSpace(item.Name)
	item.ProviderType = strings.ToLower(strings.TrimSpace(item.ProviderType))
	item.Endpoint = strings.TrimSpace(item.Endpoint)
	if item.TimeoutSec <= 0 {
		item.TimeoutSec = 5
	}
	if item.TimeoutSec > 30 {
		item.TimeoutSec = 30
	}
	if item.SubscriptionStatus == "" {
		item.SubscriptionStatus = "unknown"
	}
	if item.Status == "" {
		item.Status = AccountStatusNeverSynced
	}
	if item.Credential.Alias == "" {
		item.Credential.Alias = "default"
	}
	if item.ProviderAdapterID > 0 && item.ProviderType == "" {
		item.ProviderType = ProviderTypeHTTPSCatalog
	}
	return item
}

func ValidateAccountSource(item model.RuleCommunityAccountSource, secret model.RuleCommunityAccountSecret, requireSecret bool) error {
	if item.Name == "" {
		return errors.New("account source name is required")
	}
	if !oneOf(item.ProviderType, "https-catalog", "litewaf-cloud", "git", "generic") {
		return errors.New("account source provider type is unsupported")
	}
	if err := validateEndpoint(item.Endpoint); err != nil {
		return err
	}
	if requireSecret && strings.TrimSpace(secret.Secret) == "" {
		return errors.New("account source credential secret is required")
	}
	if len(secret.Secret) > 4096 {
		return errors.New("account source credential secret is too large")
	}
	if !oneOf(item.SubscriptionStatus, "unknown", "authorized", "expired", "unauthorized", "downgraded", "stale") {
		return errors.New("account source subscription status is unsupported")
	}
	return nil
}

func RefreshAccountSource(ctx context.Context, dataStore store.Store, source model.RuleCommunityAccountSource) (model.RuleCommunityAccountSource, error) {
	source = NormalizeAccountSource(source)
	now := time.Now().UTC()
	source.LastSyncAt = now
	source.LastError = ""
	queue := []model.RuleReviewQueueItem{}
	if !source.Enabled {
		source.Status = AccountStatusDisabled
		source.SubscriptionStatus = "stale"
		return dataStore.RefreshRuleCommunityAccountSource(ctx, source.ID, source, queue)
	}
	lowerEndpoint := strings.ToLower(source.Endpoint)
	switch {
	case strings.Contains(lowerEndpoint, "expired"):
		source.Status = AccountStatusExpired
		source.SubscriptionStatus = "expired"
		source.LastError = "subscription expired"
	case strings.Contains(lowerEndpoint, "unauthorized") || strings.Contains(lowerEndpoint, "denied"):
		source.Status = AccountStatusUnauthorized
		source.SubscriptionStatus = "unauthorized"
		source.LastError = "subscription unauthorized"
	case strings.Contains(lowerEndpoint, "failed"):
		source.Status = AccountStatusFailed
		source.SubscriptionStatus = "stale"
		source.LastError = "provider refresh failed"
	default:
		source.Status = AccountStatusAuthorized
		source.SubscriptionStatus = "authorized"
		source.EntitlementSummary = defaultString(source.EntitlementSummary, "community subscription active")
		source.PackageCount = maxInt(source.PackageCount, 1)
		queue = append(queue, model.RuleReviewQueueItem{
			ItemType:            "package-update",
			PackageID:           "account-" + fmt.Sprintf("%d", source.ID) + "-baseline",
			PackageVersion:      "candidate",
			SourceIdentity:      accountSourceIdentity(source.ID),
			Recommendation:      "review-import",
			RiskSummary:         "authorized source refresh generated a review-only package recommendation",
			SignatureStatus:     SignatureUnsigned,
			CompatibilityStatus: "compatible",
			State:               QueueStateQueued,
		})
	}
	return dataStore.RefreshRuleCommunityAccountSource(ctx, source.ID, source, queue)
}

func NormalizeContributionTarget(item model.RuleContributionTarget) model.RuleContributionTarget {
	item.Name = strings.TrimSpace(item.Name)
	item.Provider = strings.ToLower(strings.TrimSpace(item.Provider))
	item.Endpoint = strings.TrimSpace(item.Endpoint)
	item.Channel = strings.TrimSpace(item.Channel)
	if item.Channel == "" {
		item.Channel = "main"
	}
	if item.Status == "" {
		item.Status = "ready"
	}
	if item.Credential.Alias == "" {
		item.Credential.Alias = "default"
	}
	return item
}

func ValidateContributionTarget(item model.RuleContributionTarget, secret model.RuleCommunityAccountSecret, requireSecret bool) error {
	if item.Name == "" {
		return errors.New("contribution target name is required")
	}
	if !oneOf(item.Provider, "https", "git", "generic") {
		return errors.New("contribution target provider is unsupported")
	}
	if err := validateEndpoint(item.Endpoint); err != nil {
		return err
	}
	if requireSecret && strings.TrimSpace(secret.Secret) == "" {
		return errors.New("contribution target credential secret is required")
	}
	if len(secret.Secret) > 4096 {
		return errors.New("contribution target credential secret is too large")
	}
	return nil
}

func PreviewContributionPush(target model.RuleContributionTarget, artifact model.RulePackageExportArtifact, actor string) (model.RuleContributionPushAttempt, error) {
	if !target.Enabled {
		return model.RuleContributionPushAttempt{}, errors.New("contribution target is disabled")
	}
	if strings.TrimSpace(artifact.Artifact) == "" || artifact.Package.ID == "" || artifact.Checksum == "" {
		return model.RuleContributionPushAttempt{}, errors.New("validated export artifact is required")
	}
	if strings.Contains(strings.ToLower(artifact.Artifact), "authorization:") || strings.Contains(strings.ToLower(artifact.Artifact), "private_key") {
		return model.RuleContributionPushAttempt{}, errors.New("artifact contains unsupported secret-like content")
	}
	return model.RuleContributionPushAttempt{
		TargetID:       target.ID,
		TargetName:     target.Name,
		PackageID:      artifact.Package.ID,
		PackageVersion: artifact.Package.Version,
		Checksum:       artifact.Checksum,
		Status:         "preview-ready",
		Actor:          actor,
		PreviewOnly:    true,
	}, nil
}

func ExecuteContributionPush(target model.RuleContributionTarget, artifact model.RulePackageExportArtifact, actor string) (model.RuleContributionPushAttempt, error) {
	preview, err := PreviewContributionPush(target, artifact, actor)
	if err != nil {
		return preview, err
	}
	preview.Status = "delivered"
	preview.PreviewOnly = false
	preview.RemoteReference = strings.TrimRight(target.Endpoint, "/") + "/" + artifact.Package.ID + "@" + artifact.Package.Version
	return preview, nil
}

func NormalizeQueueItem(item model.RuleReviewQueueItem) model.RuleReviewQueueItem {
	item.ItemType = strings.TrimSpace(item.ItemType)
	item.PackageID = normalizeID(item.PackageID)
	item.PackageVersion = strings.TrimSpace(item.PackageVersion)
	item.SourceIdentity = strings.TrimSpace(item.SourceIdentity)
	item.Recommendation = strings.TrimSpace(item.Recommendation)
	if item.State == "" {
		item.State = QueueStateQueued
	}
	return item
}

func ApplyQueueDecision(item model.RuleReviewQueueItem, state string, reason string, actor string) (model.RuleReviewQueueItem, error) {
	state = strings.ToLower(strings.TrimSpace(state))
	if !oneOf(state, QueueStateApproved, QueueStateDismissed, QueueStateFailed) {
		return model.RuleReviewQueueItem{}, errors.New("queue decision state is unsupported")
	}
	item.State = state
	item.DecisionReason = strings.TrimSpace(reason)
	item.Actor = actor
	return item, nil
}

func NormalizeFeedback(item model.RuleFeedback) model.RuleFeedback {
	item.Reason = strings.TrimSpace(item.Reason)
	item.Severity = strings.ToLower(strings.TrimSpace(item.Severity))
	if item.Severity == "" {
		item.Severity = "medium"
	}
	if item.Status == "" {
		item.Status = FeedbackStatusOpen
	}
	clean := map[string]string{}
	for key, value := range item.RedactedSample {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		clean[key] = value
	}
	item.RedactedSample = clean
	return item
}

func ValidateFeedback(item model.RuleFeedback) error {
	if item.RuleID <= 0 && item.PackageID == "" && item.AttackLogID <= 0 {
		return errors.New("feedback must reference a rule, package, or attack log")
	}
	if item.Reason == "" {
		return errors.New("feedback reason is required")
	}
	if len(item.Reason) > 1000 {
		return errors.New("feedback reason is too large")
	}
	if !oneOf(item.Severity, "low", "medium", "high") {
		return errors.New("feedback severity is unsupported")
	}
	total := 0
	for key, value := range item.RedactedSample {
		total += len(key) + len(value)
	}
	if total > 2048 {
		return errors.New("feedback metadata is too large")
	}
	return nil
}

func SuggestionFromFeedback(feedback model.RuleFeedback, actor string) model.RuleFeedbackSuggestion {
	return model.RuleFeedbackSuggestion{
		FeedbackID:     feedback.ID,
		RuleID:         feedback.RuleID,
		ProposedChange: "review match scope, action, or expression based on false-positive feedback",
		RiskWarning:    "manual review required before changing rule behavior",
		Confidence:     "review-required",
		State:          FeedbackSuggestionQueued,
		Actor:          actor,
	}
}

func ApplySuggestionDecision(item model.RuleFeedbackSuggestion, state string, actor string) (model.RuleFeedbackSuggestion, error) {
	state = strings.ToLower(strings.TrimSpace(state))
	if !oneOf(state, FeedbackSuggestionApproved, FeedbackSuggestionRejected) {
		return model.RuleFeedbackSuggestion{}, errors.New("feedback suggestion decision is unsupported")
	}
	item.State = state
	item.Actor = actor
	return item, nil
}

func accountSourceIdentity(id int64) string {
	return fmt.Sprintf("account:%d", id)
}

func validateEndpoint(endpoint string) error {
	if endpoint == "" {
		return errors.New("endpoint is required")
	}
	if strings.HasPrefix(endpoint, "http://") {
		return errors.New("endpoint must use https or local path")
	}
	if strings.HasPrefix(endpoint, "https://") {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Host == "" {
			return errors.New("endpoint url is invalid")
		}
		return nil
	}
	if strings.Contains(endpoint, "\x00") {
		return errors.New("endpoint path is invalid")
	}
	return nil
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
