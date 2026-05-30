package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"litewaf-api/internal/model"
)

type PostgresStore struct {
	db *sql.DB
}

func (s *PostgresStore) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.db.PingContext(ctx)
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

func (s *PostgresStore) ListSites(ctx context.Context) ([]model.Site, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, host, upstream, mode, enabled, created_at, updated_at
		FROM sites
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.Site
	for rows.Next() {
		var item model.Site
		if err := rows.Scan(&item.ID, &item.Name, &item.Host, &item.Upstream, &item.Mode, &item.Enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetSite(ctx context.Context, id int64) (model.Site, error) {
	var item model.Site
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, host, upstream, mode, enabled, created_at, updated_at
		FROM sites
		WHERE id = $1`, id).
		Scan(&item.ID, &item.Name, &item.Host, &item.Upstream, &item.Mode, &item.Enabled, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Site{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateSite(ctx context.Context, site model.Site) (model.Site, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO sites (name, host, upstream, mode, enabled)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`,
		site.Name, site.Host, site.Upstream, site.Mode, site.Enabled).
		Scan(&site.ID, &site.CreatedAt, &site.UpdatedAt)
	return site, err
}

func (s *PostgresStore) UpdateSite(ctx context.Context, id int64, site model.Site) (model.Site, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE sites
		SET name = $2, host = $3, upstream = $4, mode = $5, enabled = $6, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, site.Name, site.Host, site.Upstream, site.Mode, site.Enabled).
		Scan(&site.ID, &site.CreatedAt, &site.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Site{}, ErrNotFound
	}
	return site, err
}

func (s *PostgresStore) DeleteSite(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sites WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListRules(ctx context.Context) ([]model.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, type, target, action, expression, score, enabled, created_at, updated_at
		FROM rules
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.Rule
	for rows.Next() {
		var item model.Rule
		if err := rows.Scan(&item.ID, &item.Name, &item.Type, &item.Target, &item.Action, &item.Expression, &item.Score, &item.Enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRule(ctx context.Context, id int64) (model.Rule, error) {
	var item model.Rule
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, type, target, action, expression, score, enabled, created_at, updated_at
		FROM rules
		WHERE id = $1`, id).
		Scan(&item.ID, &item.Name, &item.Type, &item.Target, &item.Action, &item.Expression, &item.Score, &item.Enabled, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Rule{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateRule(ctx context.Context, rule model.Rule) (model.Rule, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rules (name, type, target, action, expression, score, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`,
		rule.Name, rule.Type, rule.Target, rule.Action, rule.Expression, rule.Score, rule.Enabled).
		Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)
	return rule, err
}

func (s *PostgresStore) UpdateRule(ctx context.Context, id int64, rule model.Rule) (model.Rule, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE rules
		SET name = $2, type = $3, target = $4, action = $5, expression = $6, score = $7, enabled = $8, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, rule.Name, rule.Type, rule.Target, rule.Action, rule.Expression, rule.Score, rule.Enabled).
		Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Rule{}, ErrNotFound
	}
	return rule, err
}

func (s *PostgresStore) DeleteRule(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListPolicies(ctx context.Context) ([]model.Policy, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, risk_threshold, default_action, enabled, created_at, updated_at
		FROM policies
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.Policy
	for rows.Next() {
		var item model.Policy
		if err := rows.Scan(&item.ID, &item.Name, &item.RiskThreshold, &item.DefaultAction, &item.Enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.SiteIDs, item.RuleIDs, err = s.policyBindings(ctx, item.ID)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetPolicy(ctx context.Context, id int64) (model.Policy, error) {
	var item model.Policy
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, risk_threshold, default_action, enabled, created_at, updated_at
		FROM policies
		WHERE id = $1`, id).
		Scan(&item.ID, &item.Name, &item.RiskThreshold, &item.DefaultAction, &item.Enabled, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Policy{}, ErrNotFound
	}
	if err != nil {
		return model.Policy{}, err
	}
	item.SiteIDs, item.RuleIDs, err = s.policyBindings(ctx, id)
	return item, err
}

func (s *PostgresStore) CreatePolicy(ctx context.Context, policy model.Policy) (model.Policy, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Policy{}, err
	}
	defer tx.Rollback()

	if err := validateRefs(ctx, tx, "sites", policy.SiteIDs); err != nil {
		return model.Policy{}, err
	}
	if err := validateRefs(ctx, tx, "rules", policy.RuleIDs); err != nil {
		return model.Policy{}, err
	}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO policies (name, risk_threshold, default_action, enabled)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`,
		policy.Name, policy.RiskThreshold, policy.DefaultAction, policy.Enabled).
		Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return model.Policy{}, err
	}
	if err := replacePolicyBindings(ctx, tx, policy.ID, policy.SiteIDs, policy.RuleIDs); err != nil {
		return model.Policy{}, err
	}
	return policy, tx.Commit()
}

func (s *PostgresStore) UpdatePolicy(ctx context.Context, id int64, policy model.Policy) (model.Policy, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Policy{}, err
	}
	defer tx.Rollback()

	if err := validateRefs(ctx, tx, "sites", policy.SiteIDs); err != nil {
		return model.Policy{}, err
	}
	if err := validateRefs(ctx, tx, "rules", policy.RuleIDs); err != nil {
		return model.Policy{}, err
	}
	err = tx.QueryRowContext(ctx, `
		UPDATE policies
		SET name = $2, risk_threshold = $3, default_action = $4, enabled = $5, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, policy.Name, policy.RiskThreshold, policy.DefaultAction, policy.Enabled).
		Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Policy{}, ErrNotFound
	}
	if err != nil {
		return model.Policy{}, err
	}
	if err := replacePolicyBindings(ctx, tx, policy.ID, policy.SiteIDs, policy.RuleIDs); err != nil {
		return model.Policy{}, err
	}
	return policy, tx.Commit()
}

func (s *PostgresStore) DeletePolicy(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListPublishRecords(ctx context.Context) ([]model.PublishRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, version, operator, status, config_path, checksum, note, created_at
		FROM publish_records
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.PublishRecord
	for rows.Next() {
		var item model.PublishRecord
		if err := rows.Scan(&item.ID, &item.Version, &item.Operator, &item.Status, &item.ConfigPath, &item.Checksum, &item.Note, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) CreatePublishRecord(ctx context.Context, record model.PublishRecord) (model.PublishRecord, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO publish_records (version, operator, status, config_path, checksum, note)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at`,
		record.Version, record.Operator, record.Status, record.ConfigPath, record.Checksum, record.Note).
		Scan(&record.ID, &record.CreatedAt)
	record.Time = record.CreatedAt.Format(time.RFC3339)
	return record, err
}

func (s *PostgresStore) NextPublishVersion(ctx context.Context) (int64, error) {
	var value int64
	err := s.db.QueryRowContext(ctx, `SELECT count(*) + 1 FROM publish_records`).Scan(&value)
	return value, err
}

func (s *PostgresStore) policyBindings(ctx context.Context, policyID int64) ([]int64, []int64, error) {
	siteIDs, err := queryIDs(ctx, s.db, `SELECT site_id FROM policy_sites WHERE policy_id = $1 ORDER BY site_id`, policyID)
	if err != nil {
		return nil, nil, err
	}
	ruleIDs, err := queryIDs(ctx, s.db, `SELECT rule_id FROM policy_rules WHERE policy_id = $1 ORDER BY rule_id`, policyID)
	return siteIDs, ruleIDs, err
}

func checkRowsAffected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func queryIDs(ctx context.Context, db *sql.DB, query string, args ...any) ([]int64, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func validateRefs(ctx context.Context, tx *sql.Tx, table string, ids []int64) error {
	for _, id := range ids {
		var exists bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+" WHERE id = $1)", id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
	}
	return nil
}

func replacePolicyBindings(ctx context.Context, tx *sql.Tx, policyID int64, siteIDs []int64, ruleIDs []int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_sites WHERE policy_id = $1`, policyID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_rules WHERE policy_id = $1`, policyID); err != nil {
		return err
	}
	for _, id := range siteIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_sites (policy_id, site_id) VALUES ($1, $2)`, policyID, id); err != nil {
			return err
		}
	}
	for _, id := range ruleIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_rules (policy_id, rule_id) VALUES ($1, $2)`, policyID, id); err != nil {
			return err
		}
	}
	return nil
}
