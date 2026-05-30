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
