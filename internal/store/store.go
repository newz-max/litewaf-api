package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"

	"litewaf-api/internal/model"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	Ping(context.Context) error
	Close() error

	ListSites(context.Context) ([]model.Site, error)
	GetSite(context.Context, int64) (model.Site, error)
	CreateSite(context.Context, model.Site) (model.Site, error)
	UpdateSite(context.Context, int64, model.Site) (model.Site, error)
	DeleteSite(context.Context, int64) error

	ListRules(context.Context) ([]model.Rule, error)
	GetRule(context.Context, int64) (model.Rule, error)
	CreateRule(context.Context, model.Rule) (model.Rule, error)
	UpdateRule(context.Context, int64, model.Rule) (model.Rule, error)
	DeleteRule(context.Context, int64) error

	ListPolicies(context.Context) ([]model.Policy, error)
	GetPolicy(context.Context, int64) (model.Policy, error)
	CreatePolicy(context.Context, model.Policy) (model.Policy, error)
	UpdatePolicy(context.Context, int64, model.Policy) (model.Policy, error)
	DeletePolicy(context.Context, int64) error

	ListPublishRecords(context.Context) ([]model.PublishRecord, error)
	CreatePublishRecord(context.Context, model.PublishRecord) (model.PublishRecord, error)
	NextPublishVersion(context.Context) (int64, error)
	GetPublishRecordByVersion(context.Context, string) (model.PublishRecord, error)

	GetUserByUsername(context.Context, string) (model.User, error)
	EnsureUser(context.Context, model.User) (model.User, error)

	ListAuditLogs(context.Context, model.AuditLogFilter) ([]model.AuditLog, error)
	CreateAuditLog(context.Context, model.AuditLog) (model.AuditLog, error)

	CreateAccessLog(context.Context, model.AccessLog) (model.AccessLog, error)
	ListAccessLogs(context.Context, model.AccessLogFilter) ([]model.AccessLog, error)
	CreateWAFEvent(context.Context, model.WAFEvent) (model.WAFEvent, error)
	ListWAFEvents(context.Context, model.WAFEventFilter) ([]model.WAFEvent, error)
	GetObservabilitySummary(context.Context, model.ObservabilitySummaryFilter) (model.ObservabilitySummary, error)

	ListAccessListEntries(context.Context) ([]model.AccessListEntry, error)
	GetAccessListEntry(context.Context, int64) (model.AccessListEntry, error)
	CreateAccessListEntry(context.Context, model.AccessListEntry) (model.AccessListEntry, error)
	UpdateAccessListEntry(context.Context, int64, model.AccessListEntry) (model.AccessListEntry, error)
	DeleteAccessListEntry(context.Context, int64) error

	ListRateLimitRules(context.Context) ([]model.RateLimitRule, error)
	GetRateLimitRule(context.Context, int64) (model.RateLimitRule, error)
	CreateRateLimitRule(context.Context, model.RateLimitRule) (model.RateLimitRule, error)
	UpdateRateLimitRule(context.Context, int64, model.RateLimitRule) (model.RateLimitRule, error)
	DeleteRateLimitRule(context.Context, int64) error

	ListUploadProtectionRules(context.Context) ([]model.UploadProtectionRule, error)
	GetUploadProtectionRule(context.Context, int64) (model.UploadProtectionRule, error)
	CreateUploadProtectionRule(context.Context, model.UploadProtectionRule) (model.UploadProtectionRule, error)
	UpdateUploadProtectionRule(context.Context, int64, model.UploadProtectionRule) (model.UploadProtectionRule, error)
	DeleteUploadProtectionRule(context.Context, int64) error

	ListBotProtectionRules(context.Context) ([]model.BotProtectionRule, error)
	GetBotProtectionRule(context.Context, int64) (model.BotProtectionRule, error)
	CreateBotProtectionRule(context.Context, model.BotProtectionRule) (model.BotProtectionRule, error)
	UpdateBotProtectionRule(context.Context, int64, model.BotProtectionRule) (model.BotProtectionRule, error)
	DeleteBotProtectionRule(context.Context, int64) error

	ListDynamicProtectionRules(context.Context) ([]model.DynamicProtectionRule, error)
	GetDynamicProtectionRule(context.Context, int64) (model.DynamicProtectionRule, error)
	CreateDynamicProtectionRule(context.Context, model.DynamicProtectionRule) (model.DynamicProtectionRule, error)
	UpdateDynamicProtectionRule(context.Context, int64, model.DynamicProtectionRule) (model.DynamicProtectionRule, error)
	DeleteDynamicProtectionRule(context.Context, int64) error

	ListProtectionRules(context.Context) ([]model.ProtectionRule, error)
	GetProtectionRule(context.Context, int64) (model.ProtectionRule, error)
	CreateProtectionRule(context.Context, model.ProtectionRule) (model.ProtectionRule, error)
	UpdateProtectionRule(context.Context, int64, model.ProtectionRule) (model.ProtectionRule, error)
	DeleteProtectionRule(context.Context, int64) error
	BackfillProtectionRules(context.Context) (int, error)

	ListRuleCatalogSources(context.Context) ([]model.RuleCatalogSource, error)
	GetRuleCatalogSource(context.Context, int64) (model.RuleCatalogSource, error)
	CreateRuleCatalogSource(context.Context, model.RuleCatalogSource) (model.RuleCatalogSource, error)
	UpdateRuleCatalogSource(context.Context, int64, model.RuleCatalogSource) (model.RuleCatalogSource, error)
	DeleteRuleCatalogSource(context.Context, int64) error
	ListRuleCatalogPackages(context.Context, int64) ([]model.RuleCatalogPackage, error)
	GetRuleCatalogPackage(context.Context, int64, string) (model.RuleCatalogPackage, error)
	ReplaceRuleCatalogPackages(context.Context, int64, []model.RuleCatalogPackage) error

	ListRuleTrustKeys(context.Context) ([]model.RuleTrustKey, error)
	GetRuleTrustKey(context.Context, string) (model.RuleTrustKey, error)
	CreateRuleTrustKey(context.Context, model.RuleTrustKey) (model.RuleTrustKey, error)
	UpdateRuleTrustKey(context.Context, int64, model.RuleTrustKey) (model.RuleTrustKey, error)
}

func OpenPostgres(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	store := &PostgresStore{db: db}
	if err := store.Ping(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}
