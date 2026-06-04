package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"litewaf-api/internal/attackmeta"
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
		SELECT id, name, type, target, action, expression, score, enabled, module, category, attack_type, group_name, priority,
			package_id, package_version, package_rule_id, source_checksum, signature_status, review_status, last_test_status,
			remote_catalog_id, last_synced_version, pending_update_state, local_override_state, export_eligible, export_ineligible_reasons,
			created_at, updated_at
		FROM rules
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.Rule
	for rows.Next() {
		var item model.Rule
		var exportReasons string
		if err := rows.Scan(
			&item.ID, &item.Name, &item.Type, &item.Target, &item.Action, &item.Expression, &item.Score,
			&item.Enabled, &item.Module, &item.Category, &item.AttackType, &item.Group, &item.Priority,
			&item.PackageID, &item.PackageVersion, &item.PackageRuleID, &item.SourceChecksum,
			&item.SignatureStatus, &item.ReviewStatus, &item.LastTestStatus,
			&item.RemoteCatalogID, &item.LastSyncedVersion, &item.PendingUpdateState, &item.LocalOverrideState, &item.ExportEligible, &exportReasons,
			&item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		item.ExportIneligibleReasons = splitCSV(exportReasons)
		item = attackmeta.NormalizeRule(item)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRule(ctx context.Context, id int64) (model.Rule, error) {
	var item model.Rule
	var exportReasons string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, type, target, action, expression, score, enabled, module, category, attack_type, group_name, priority,
			package_id, package_version, package_rule_id, source_checksum, signature_status, review_status, last_test_status,
			remote_catalog_id, last_synced_version, pending_update_state, local_override_state, export_eligible, export_ineligible_reasons,
			created_at, updated_at
		FROM rules
		WHERE id = $1`, id).
		Scan(
			&item.ID, &item.Name, &item.Type, &item.Target, &item.Action, &item.Expression, &item.Score,
			&item.Enabled, &item.Module, &item.Category, &item.AttackType, &item.Group, &item.Priority,
			&item.PackageID, &item.PackageVersion, &item.PackageRuleID, &item.SourceChecksum,
			&item.SignatureStatus, &item.ReviewStatus, &item.LastTestStatus,
			&item.RemoteCatalogID, &item.LastSyncedVersion, &item.PendingUpdateState, &item.LocalOverrideState, &item.ExportEligible, &exportReasons,
			&item.CreatedAt, &item.UpdatedAt,
		)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Rule{}, ErrNotFound
	}
	item.ExportIneligibleReasons = splitCSV(exportReasons)
	return attackmeta.NormalizeRule(item), err
}

func (s *PostgresStore) CreateRule(ctx context.Context, rule model.Rule) (model.Rule, error) {
	rule = attackmeta.NormalizeRule(rule)
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rules (
			name, type, target, action, expression, score, enabled, module, category, attack_type, group_name, priority,
			package_id, package_version, package_rule_id, source_checksum, signature_status, review_status, last_test_status,
			remote_catalog_id, last_synced_version, pending_update_state, local_override_state, export_eligible, export_ineligible_reasons
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)
		RETURNING id, created_at, updated_at`,
		rule.Name, rule.Type, rule.Target, rule.Action, rule.Expression, rule.Score, rule.Enabled,
		rule.Module, rule.Category, rule.AttackType, rule.Group, rule.Priority,
		rule.PackageID, rule.PackageVersion, rule.PackageRuleID, rule.SourceChecksum,
		rule.SignatureStatus, rule.ReviewStatus, rule.LastTestStatus,
		rule.RemoteCatalogID, rule.LastSyncedVersion, rule.PendingUpdateState, rule.LocalOverrideState, rule.ExportEligible, joinCSV(rule.ExportIneligibleReasons)).
		Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)
	return rule, err
}

func (s *PostgresStore) UpdateRule(ctx context.Context, id int64, rule model.Rule) (model.Rule, error) {
	rule = attackmeta.NormalizeRule(rule)
	err := s.db.QueryRowContext(ctx, `
		UPDATE rules
		SET name = $2, type = $3, target = $4, action = $5, expression = $6, score = $7, enabled = $8,
			module = $9, category = $10, attack_type = $11, group_name = $12, priority = $13,
			package_id = $14, package_version = $15, package_rule_id = $16, source_checksum = $17,
			signature_status = $18, review_status = $19, last_test_status = $20,
			remote_catalog_id = $21, last_synced_version = $22, pending_update_state = $23,
			local_override_state = $24, export_eligible = $25, export_ineligible_reasons = $26, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, rule.Name, rule.Type, rule.Target, rule.Action, rule.Expression, rule.Score, rule.Enabled,
		rule.Module, rule.Category, rule.AttackType, rule.Group, rule.Priority,
		rule.PackageID, rule.PackageVersion, rule.PackageRuleID, rule.SourceChecksum,
		rule.SignatureStatus, rule.ReviewStatus, rule.LastTestStatus,
		rule.RemoteCatalogID, rule.LastSyncedVersion, rule.PendingUpdateState, rule.LocalOverrideState, rule.ExportEligible, joinCSV(rule.ExportIneligibleReasons)).
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
		SELECT id, name, risk_threshold, default_action,
			normalization_enabled, normalization_decode_passes, normalization_max_value_bytes,
			body_inspection_enabled, body_inspection_content_types, body_inspection_path_prefixes,
			body_inspection_max_bytes, oversized_body_action,
			upload_inspection_enabled, upload_max_bytes, upload_size_action,
			dynamic_ban_enabled, dynamic_ban_duration_sec, dynamic_ban_score_threshold,
			dynamic_ban_trigger_count, dynamic_ban_window_sec,
			enabled, created_at, updated_at
		FROM policies
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.Policy
	for rows.Next() {
		var item model.Policy
		var bodyContentTypes string
		var bodyPathPrefixes string
		if err := rows.Scan(
			&item.ID, &item.Name, &item.RiskThreshold, &item.DefaultAction,
			&item.NormalizationEnabled, &item.NormalizationDecodePasses, &item.NormalizationMaxValueBytes,
			&item.BodyInspectionEnabled, &bodyContentTypes, &bodyPathPrefixes,
			&item.BodyInspectionMaxBytes, &item.OversizedBodyAction,
			&item.UploadInspectionEnabled, &item.UploadMaxBytes, &item.UploadSizeAction,
			&item.DynamicBanEnabled, &item.DynamicBanDurationSec, &item.DynamicBanScoreThreshold,
			&item.DynamicBanTriggerCount, &item.DynamicBanWindowSec,
			&item.Enabled, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		item.BodyInspectionContentTypes = splitCSV(bodyContentTypes)
		item.BodyInspectionPathPrefixes = splitCSV(bodyPathPrefixes)
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
	var bodyContentTypes string
	var bodyPathPrefixes string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, risk_threshold, default_action,
			normalization_enabled, normalization_decode_passes, normalization_max_value_bytes,
			body_inspection_enabled, body_inspection_content_types, body_inspection_path_prefixes,
			body_inspection_max_bytes, oversized_body_action,
			upload_inspection_enabled, upload_max_bytes, upload_size_action,
			dynamic_ban_enabled, dynamic_ban_duration_sec, dynamic_ban_score_threshold,
			dynamic_ban_trigger_count, dynamic_ban_window_sec,
			enabled, created_at, updated_at
		FROM policies
		WHERE id = $1`, id).
		Scan(
			&item.ID, &item.Name, &item.RiskThreshold, &item.DefaultAction,
			&item.NormalizationEnabled, &item.NormalizationDecodePasses, &item.NormalizationMaxValueBytes,
			&item.BodyInspectionEnabled, &bodyContentTypes, &bodyPathPrefixes,
			&item.BodyInspectionMaxBytes, &item.OversizedBodyAction,
			&item.UploadInspectionEnabled, &item.UploadMaxBytes, &item.UploadSizeAction,
			&item.DynamicBanEnabled, &item.DynamicBanDurationSec, &item.DynamicBanScoreThreshold,
			&item.DynamicBanTriggerCount, &item.DynamicBanWindowSec,
			&item.Enabled, &item.CreatedAt, &item.UpdatedAt,
		)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Policy{}, ErrNotFound
	}
	if err != nil {
		return model.Policy{}, err
	}
	item.BodyInspectionContentTypes = splitCSV(bodyContentTypes)
	item.BodyInspectionPathPrefixes = splitCSV(bodyPathPrefixes)
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
		INSERT INTO policies (
			name, risk_threshold, default_action,
			normalization_enabled, normalization_decode_passes, normalization_max_value_bytes,
			body_inspection_enabled, body_inspection_content_types, body_inspection_path_prefixes,
			body_inspection_max_bytes, oversized_body_action,
			upload_inspection_enabled, upload_max_bytes, upload_size_action,
			dynamic_ban_enabled, dynamic_ban_duration_sec, dynamic_ban_score_threshold,
			dynamic_ban_trigger_count, dynamic_ban_window_sec,
			enabled
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		RETURNING id, created_at, updated_at`,
		policy.Name, policy.RiskThreshold, policy.DefaultAction,
		policy.NormalizationEnabled, policy.NormalizationDecodePasses, policy.NormalizationMaxValueBytes,
		policy.BodyInspectionEnabled, joinCSV(policy.BodyInspectionContentTypes), joinCSV(policy.BodyInspectionPathPrefixes),
		policy.BodyInspectionMaxBytes, policy.OversizedBodyAction,
		policy.UploadInspectionEnabled, policy.UploadMaxBytes, policy.UploadSizeAction,
		policy.DynamicBanEnabled, policy.DynamicBanDurationSec, policy.DynamicBanScoreThreshold,
		policy.DynamicBanTriggerCount, policy.DynamicBanWindowSec,
		policy.Enabled).
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
		SET name = $2,
			risk_threshold = $3,
			default_action = $4,
			normalization_enabled = $5,
			normalization_decode_passes = $6,
			normalization_max_value_bytes = $7,
			body_inspection_enabled = $8,
			body_inspection_content_types = $9,
			body_inspection_path_prefixes = $10,
			body_inspection_max_bytes = $11,
			oversized_body_action = $12,
			upload_inspection_enabled = $13,
			upload_max_bytes = $14,
			upload_size_action = $15,
			dynamic_ban_enabled = $16,
			dynamic_ban_duration_sec = $17,
			dynamic_ban_score_threshold = $18,
			dynamic_ban_trigger_count = $19,
			dynamic_ban_window_sec = $20,
			enabled = $21,
			updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, policy.Name, policy.RiskThreshold, policy.DefaultAction,
		policy.NormalizationEnabled, policy.NormalizationDecodePasses, policy.NormalizationMaxValueBytes,
		policy.BodyInspectionEnabled, joinCSV(policy.BodyInspectionContentTypes), joinCSV(policy.BodyInspectionPathPrefixes),
		policy.BodyInspectionMaxBytes, policy.OversizedBodyAction,
		policy.UploadInspectionEnabled, policy.UploadMaxBytes, policy.UploadSizeAction,
		policy.DynamicBanEnabled, policy.DynamicBanDurationSec, policy.DynamicBanScoreThreshold,
		policy.DynamicBanTriggerCount, policy.DynamicBanWindowSec,
		policy.Enabled).
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
		SELECT id, version, operator, status, config_path, checksum, note, config_json, created_at
		FROM publish_records
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.PublishRecord
	for rows.Next() {
		var item model.PublishRecord
		if err := rows.Scan(&item.ID, &item.Version, &item.Operator, &item.Status, &item.ConfigPath, &item.Checksum, &item.Note, &item.ConfigJSON, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) CreatePublishRecord(ctx context.Context, record model.PublishRecord) (model.PublishRecord, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO publish_records (version, operator, status, config_path, checksum, note, config_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		record.Version, record.Operator, record.Status, record.ConfigPath, record.Checksum, record.Note, record.ConfigJSON).
		Scan(&record.ID, &record.CreatedAt)
	record.Time = record.CreatedAt.Format(time.RFC3339)
	return record, err
}

func (s *PostgresStore) NextPublishVersion(ctx context.Context) (int64, error) {
	var value int64
	err := s.db.QueryRowContext(ctx, `SELECT count(*) + 1 FROM publish_records`).Scan(&value)
	return value, err
}

func (s *PostgresStore) GetPublishRecordByVersion(ctx context.Context, version string) (model.PublishRecord, error) {
	var item model.PublishRecord
	err := s.db.QueryRowContext(ctx, `
		SELECT id, version, operator, status, config_path, checksum, note, config_json, created_at
		FROM publish_records
		WHERE version = $1`, version).
		Scan(&item.ID, &item.Version, &item.Operator, &item.Status, &item.ConfigPath, &item.Checksum, &item.Note, &item.ConfigJSON, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.PublishRecord{}, ErrNotFound
	}
	item.Time = item.CreatedAt.Format(time.RFC3339)
	return item, err
}

func (s *PostgresStore) GetUserByUsername(ctx context.Context, username string) (model.User, error) {
	var item model.User
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, role, enabled, created_at, updated_at
		FROM users
		WHERE username = $1`, username).
		Scan(&item.ID, &item.Username, &item.PasswordHash, &item.Role, &item.Enabled, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) EnsureUser(ctx context.Context, user model.User) (model.User, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO users (username, password_hash, role, enabled)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (username) DO UPDATE
		SET password_hash = EXCLUDED.password_hash,
			role = EXCLUDED.role,
			enabled = EXCLUDED.enabled,
			updated_at = now()
		RETURNING id, created_at, updated_at`,
		user.Username, user.PasswordHash, user.Role, user.Enabled).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	return user, err
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, filter model.AuditLogFilter) ([]model.AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, actor, role, action, resource_type, resource_id, result, remote_addr, user_agent, message, created_at
		FROM audit_logs
		WHERE ($1 = '' OR actor = $1)
			AND ($2 = '' OR action = $2)
			AND ($3 = '' OR resource_type = $3)
			AND ($4 = '' OR result = $4)
			AND ($5::timestamptz IS NULL OR created_at >= $5)
			AND ($6::timestamptz IS NULL OR created_at <= $6)
		ORDER BY id DESC`,
		filter.Actor, filter.Action, filter.ResourceType, filter.Result, nullableTime(filter.Since), nullableTime(filter.Until))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.AuditLog
	for rows.Next() {
		var item model.AuditLog
		if err := rows.Scan(&item.ID, &item.Actor, &item.Role, &item.Action, &item.ResourceType, &item.ResourceID, &item.Result, &item.RemoteAddr, &item.UserAgent, &item.Message, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) CreateAuditLog(ctx context.Context, item model.AuditLog) (model.AuditLog, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO audit_logs (actor, role, action, resource_type, resource_id, result, remote_addr, user_agent, message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at`,
		item.Actor, item.Role, item.Action, item.ResourceType, item.ResourceID, item.Result, item.RemoteAddr, item.UserAgent, item.Message).
		Scan(&item.ID, &item.CreatedAt)
	item.Time = item.CreatedAt.Format(time.RFC3339)
	return item, err
}

func (s *PostgresStore) ListAccessListEntries(ctx context.Context) ([]model.AccessListEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, kind, target, value, match_operator, header_name, action, site_id, enabled, priority, created_at, updated_at
		FROM access_list_entries
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.AccessListEntry
	for rows.Next() {
		var item model.AccessListEntry
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.Target, &item.Value, &item.MatchOperator, &item.HeaderName, &item.Action, &item.SiteID, &item.Enabled, &item.Priority, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetAccessListEntry(ctx context.Context, id int64) (model.AccessListEntry, error) {
	var item model.AccessListEntry
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, kind, target, value, match_operator, header_name, action, site_id, enabled, priority, created_at, updated_at
		FROM access_list_entries
		WHERE id = $1`, id).
		Scan(&item.ID, &item.Name, &item.Kind, &item.Target, &item.Value, &item.MatchOperator, &item.HeaderName, &item.Action, &item.SiteID, &item.Enabled, &item.Priority, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AccessListEntry{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateAccessListEntry(ctx context.Context, item model.AccessListEntry) (model.AccessListEntry, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO access_list_entries (name, kind, target, value, match_operator, header_name, action, site_id, enabled, priority)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Kind, item.Target, item.Value, item.MatchOperator, item.HeaderName, item.Action, item.SiteID, item.Enabled, item.Priority).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateAccessListEntry(ctx context.Context, id int64, item model.AccessListEntry) (model.AccessListEntry, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE access_list_entries
		SET name = $2, kind = $3, target = $4, value = $5, match_operator = $6, header_name = $7, action = $8, site_id = $9, enabled = $10, priority = $11, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Kind, item.Target, item.Value, item.MatchOperator, item.HeaderName, item.Action, item.SiteID, item.Enabled, item.Priority).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AccessListEntry{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) DeleteAccessListEntry(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM access_list_entries WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListRateLimitRules(ctx context.Context) ([]model.RateLimitRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, scope, match_value, path_match, methods, threshold, window_sec, action, cc_action, ban_duration_sec, violation_threshold, violation_window_sec, site_id, enabled, created_at, updated_at
		FROM rate_limit_rules
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RateLimitRule
	for rows.Next() {
		var item model.RateLimitRule
		var methods string
		if err := rows.Scan(&item.ID, &item.Name, &item.Scope, &item.MatchValue, &item.PathMatch, &methods, &item.Threshold, &item.WindowSec, &item.Action, &item.CCAction, &item.BanDuration, &item.ViolationThreshold, &item.ViolationWindowSec, &item.SiteID, &item.Enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Methods = splitMethods(methods)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRateLimitRule(ctx context.Context, id int64) (model.RateLimitRule, error) {
	var item model.RateLimitRule
	var methods string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, scope, match_value, path_match, methods, threshold, window_sec, action, cc_action, ban_duration_sec, violation_threshold, violation_window_sec, site_id, enabled, created_at, updated_at
		FROM rate_limit_rules
		WHERE id = $1`, id).
		Scan(&item.ID, &item.Name, &item.Scope, &item.MatchValue, &item.PathMatch, &methods, &item.Threshold, &item.WindowSec, &item.Action, &item.CCAction, &item.BanDuration, &item.ViolationThreshold, &item.ViolationWindowSec, &item.SiteID, &item.Enabled, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RateLimitRule{}, ErrNotFound
	}
	item.Methods = splitMethods(methods)
	return item, err
}

func (s *PostgresStore) CreateRateLimitRule(ctx context.Context, item model.RateLimitRule) (model.RateLimitRule, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rate_limit_rules (name, scope, match_value, path_match, methods, threshold, window_sec, action, cc_action, ban_duration_sec, violation_threshold, violation_window_sec, site_id, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Scope, item.MatchValue, item.PathMatch, joinMethods(item.Methods), item.Threshold, item.WindowSec, item.Action, item.CCAction, item.BanDuration, item.ViolationThreshold, item.ViolationWindowSec, item.SiteID, item.Enabled).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateRateLimitRule(ctx context.Context, id int64, item model.RateLimitRule) (model.RateLimitRule, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE rate_limit_rules
		SET name = $2, scope = $3, match_value = $4, path_match = $5, methods = $6, threshold = $7, window_sec = $8, action = $9, cc_action = $10, ban_duration_sec = $11, violation_threshold = $12, violation_window_sec = $13, site_id = $14, enabled = $15, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Scope, item.MatchValue, item.PathMatch, joinMethods(item.Methods), item.Threshold, item.WindowSec, item.Action, item.CCAction, item.BanDuration, item.ViolationThreshold, item.ViolationWindowSec, item.SiteID, item.Enabled).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RateLimitRule{}, ErrNotFound
	}
	return item, err
}

func splitMethods(value string) []string {
	if value == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func joinMethods(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ",")
}

func (s *PostgresStore) DeleteRateLimitRule(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_rules WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListUploadProtectionRules(ctx context.Context) ([]model.UploadProtectionRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, path, path_match, methods, extensions, max_bytes, action, site_id, enabled, priority, created_at, updated_at
		FROM upload_protection_rules
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.UploadProtectionRule
	for rows.Next() {
		var item model.UploadProtectionRule
		var methods string
		var extensions string
		if err := rows.Scan(&item.ID, &item.Name, &item.Path, &item.PathMatch, &methods, &extensions, &item.MaxBytes, &item.Action, &item.SiteID, &item.Enabled, &item.Priority, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Methods = splitMethods(methods)
		item.Extensions = splitCSV(extensions)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetUploadProtectionRule(ctx context.Context, id int64) (model.UploadProtectionRule, error) {
	var item model.UploadProtectionRule
	var methods string
	var extensions string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, path, path_match, methods, extensions, max_bytes, action, site_id, enabled, priority, created_at, updated_at
		FROM upload_protection_rules
		WHERE id = $1`, id).
		Scan(&item.ID, &item.Name, &item.Path, &item.PathMatch, &methods, &extensions, &item.MaxBytes, &item.Action, &item.SiteID, &item.Enabled, &item.Priority, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.UploadProtectionRule{}, ErrNotFound
	}
	item.Methods = splitMethods(methods)
	item.Extensions = splitCSV(extensions)
	return item, err
}

func (s *PostgresStore) CreateUploadProtectionRule(ctx context.Context, item model.UploadProtectionRule) (model.UploadProtectionRule, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO upload_protection_rules (name, path, path_match, methods, extensions, max_bytes, action, site_id, enabled, priority)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Path, item.PathMatch, joinMethods(item.Methods), joinCSV(item.Extensions), item.MaxBytes, item.Action, item.SiteID, item.Enabled, item.Priority).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateUploadProtectionRule(ctx context.Context, id int64, item model.UploadProtectionRule) (model.UploadProtectionRule, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE upload_protection_rules
		SET name = $2, path = $3, path_match = $4, methods = $5, extensions = $6, max_bytes = $7, action = $8, site_id = $9, enabled = $10, priority = $11, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Path, item.PathMatch, joinMethods(item.Methods), joinCSV(item.Extensions), item.MaxBytes, item.Action, item.SiteID, item.Enabled, item.Priority).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.UploadProtectionRule{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) DeleteUploadProtectionRule(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM upload_protection_rules WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListBotProtectionRules(ctx context.Context) ([]model.BotProtectionRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, path, path_match, methods, challenge_mode, verify_ttl_sec, failure_action, site_id, enabled, priority, created_at, updated_at
		FROM bot_protection_rules
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.BotProtectionRule
	for rows.Next() {
		var item model.BotProtectionRule
		var methods string
		if err := rows.Scan(&item.ID, &item.Name, &item.Path, &item.PathMatch, &methods, &item.ChallengeMode, &item.VerifyTTL, &item.FailureAction, &item.SiteID, &item.Enabled, &item.Priority, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Methods = splitMethods(methods)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetBotProtectionRule(ctx context.Context, id int64) (model.BotProtectionRule, error) {
	var item model.BotProtectionRule
	var methods string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, path, path_match, methods, challenge_mode, verify_ttl_sec, failure_action, site_id, enabled, priority, created_at, updated_at
		FROM bot_protection_rules
		WHERE id = $1`, id).
		Scan(&item.ID, &item.Name, &item.Path, &item.PathMatch, &methods, &item.ChallengeMode, &item.VerifyTTL, &item.FailureAction, &item.SiteID, &item.Enabled, &item.Priority, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.BotProtectionRule{}, ErrNotFound
	}
	item.Methods = splitMethods(methods)
	return item, err
}

func (s *PostgresStore) CreateBotProtectionRule(ctx context.Context, item model.BotProtectionRule) (model.BotProtectionRule, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO bot_protection_rules (name, path, path_match, methods, challenge_mode, verify_ttl_sec, failure_action, site_id, enabled, priority)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Path, item.PathMatch, joinMethods(item.Methods), item.ChallengeMode, item.VerifyTTL, item.FailureAction, item.SiteID, item.Enabled, item.Priority).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateBotProtectionRule(ctx context.Context, id int64, item model.BotProtectionRule) (model.BotProtectionRule, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE bot_protection_rules
		SET name = $2, path = $3, path_match = $4, methods = $5, challenge_mode = $6, verify_ttl_sec = $7, failure_action = $8, site_id = $9, enabled = $10, priority = $11, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Path, item.PathMatch, joinMethods(item.Methods), item.ChallengeMode, item.VerifyTTL, item.FailureAction, item.SiteID, item.Enabled, item.Priority).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.BotProtectionRule{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) DeleteBotProtectionRule(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM bot_protection_rules WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListDynamicProtectionRules(ctx context.Context) ([]model.DynamicProtectionRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, category, path, path_match, methods, token_ttl_sec, token_placement, failure_action,
			mutation_marker, mutation_max_bytes, queue_capacity, admission_ttl_sec, retry_interval_sec,
			overflow_action, site_id, enabled, priority, created_at, updated_at
		FROM dynamic_protection_rules
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.DynamicProtectionRule
	for rows.Next() {
		var item model.DynamicProtectionRule
		var methods string
		if err := rows.Scan(
			&item.ID, &item.Name, &item.Category, &item.Path, &item.PathMatch, &methods,
			&item.TokenTTL, &item.TokenPlacement, &item.FailureAction,
			&item.MutationMarker, &item.MutationMaxBytes, &item.QueueCapacity,
			&item.AdmissionTTL, &item.RetryInterval, &item.OverflowAction,
			&item.SiteID, &item.Enabled, &item.Priority, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		item.Methods = splitMethods(methods)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetDynamicProtectionRule(ctx context.Context, id int64) (model.DynamicProtectionRule, error) {
	var item model.DynamicProtectionRule
	var methods string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, category, path, path_match, methods, token_ttl_sec, token_placement, failure_action,
			mutation_marker, mutation_max_bytes, queue_capacity, admission_ttl_sec, retry_interval_sec,
			overflow_action, site_id, enabled, priority, created_at, updated_at
		FROM dynamic_protection_rules
		WHERE id = $1`, id).
		Scan(
			&item.ID, &item.Name, &item.Category, &item.Path, &item.PathMatch, &methods,
			&item.TokenTTL, &item.TokenPlacement, &item.FailureAction,
			&item.MutationMarker, &item.MutationMaxBytes, &item.QueueCapacity,
			&item.AdmissionTTL, &item.RetryInterval, &item.OverflowAction,
			&item.SiteID, &item.Enabled, &item.Priority, &item.CreatedAt, &item.UpdatedAt,
		)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DynamicProtectionRule{}, ErrNotFound
	}
	item.Methods = splitMethods(methods)
	return item, err
}

func (s *PostgresStore) CreateDynamicProtectionRule(ctx context.Context, item model.DynamicProtectionRule) (model.DynamicProtectionRule, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO dynamic_protection_rules (
			name, category, path, path_match, methods, token_ttl_sec, token_placement, failure_action,
			mutation_marker, mutation_max_bytes, queue_capacity, admission_ttl_sec, retry_interval_sec,
			overflow_action, site_id, enabled, priority
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Category, item.Path, item.PathMatch, joinMethods(item.Methods),
		item.TokenTTL, item.TokenPlacement, item.FailureAction,
		item.MutationMarker, item.MutationMaxBytes, item.QueueCapacity,
		item.AdmissionTTL, item.RetryInterval, item.OverflowAction,
		item.SiteID, item.Enabled, item.Priority).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateDynamicProtectionRule(ctx context.Context, id int64, item model.DynamicProtectionRule) (model.DynamicProtectionRule, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE dynamic_protection_rules
		SET name = $2, category = $3, path = $4, path_match = $5, methods = $6,
			token_ttl_sec = $7, token_placement = $8, failure_action = $9,
			mutation_marker = $10, mutation_max_bytes = $11, queue_capacity = $12,
			admission_ttl_sec = $13, retry_interval_sec = $14, overflow_action = $15,
			site_id = $16, enabled = $17, priority = $18, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Category, item.Path, item.PathMatch, joinMethods(item.Methods),
		item.TokenTTL, item.TokenPlacement, item.FailureAction,
		item.MutationMarker, item.MutationMaxBytes, item.QueueCapacity,
		item.AdmissionTTL, item.RetryInterval, item.OverflowAction,
		item.SiteID, item.Enabled, item.Priority).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DynamicProtectionRule{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) DeleteDynamicProtectionRule(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM dynamic_protection_rules WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListRuleCatalogSources(ctx context.Context) ([]model.RuleCatalogSource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.name, s.source, s.enabled, s.timeout_sec, s.status, s.last_sync_at, s.last_error, count(p.id), s.created_at, s.updated_at
		FROM rule_catalog_sources s
		LEFT JOIN rule_catalog_packages p ON p.catalog_id = s.id
		GROUP BY s.id
		ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleCatalogSource
	for rows.Next() {
		var item model.RuleCatalogSource
		var lastSync sql.NullTime
		if err := rows.Scan(&item.ID, &item.Name, &item.Source, &item.Enabled, &item.TimeoutSec, &item.Status, &lastSync, &item.LastError, &item.PackageCount, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if lastSync.Valid {
			item.LastSyncAt = lastSync.Time
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRuleCatalogSource(ctx context.Context, id int64) (model.RuleCatalogSource, error) {
	var item model.RuleCatalogSource
	var lastSync sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.name, s.source, s.enabled, s.timeout_sec, s.status, s.last_sync_at, s.last_error, count(p.id), s.created_at, s.updated_at
		FROM rule_catalog_sources s
		LEFT JOIN rule_catalog_packages p ON p.catalog_id = s.id
		WHERE s.id = $1
		GROUP BY s.id`, id).
		Scan(&item.ID, &item.Name, &item.Source, &item.Enabled, &item.TimeoutSec, &item.Status, &lastSync, &item.LastError, &item.PackageCount, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleCatalogSource{}, ErrNotFound
	}
	if lastSync.Valid {
		item.LastSyncAt = lastSync.Time
	}
	return item, err
}

func (s *PostgresStore) CreateRuleCatalogSource(ctx context.Context, item model.RuleCatalogSource) (model.RuleCatalogSource, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rule_catalog_sources (name, source, enabled, timeout_sec, status, last_error)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Source, item.Enabled, item.TimeoutSec, item.Status, item.LastError).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateRuleCatalogSource(ctx context.Context, id int64, item model.RuleCatalogSource) (model.RuleCatalogSource, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE rule_catalog_sources
		SET name = $2, source = $3, enabled = $4, timeout_sec = $5, status = $6, last_sync_at = $7, last_error = $8, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Source, item.Enabled, item.TimeoutSec, item.Status, nullableTime(item.LastSyncAt), item.LastError).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleCatalogSource{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) DeleteRuleCatalogSource(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM rule_catalog_sources WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListRuleCatalogPackages(ctx context.Context, catalogID int64) ([]model.RuleCatalogPackage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, catalog_id, package_id, name, version, compatibility, checksum,
			signature_key_id, signature_checksum, signature_value, signature_expires_at, signature_status,
			updated_at_text, manifest_url, package_json, source_identity, sync_status, stale, last_synced_at, created_at, updated_at
		FROM rule_catalog_packages
		WHERE ($1 = 0 OR catalog_id = $1)
		ORDER BY catalog_id, package_id`, catalogID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleCatalogPackage
	for rows.Next() {
		item, err := scanRuleCatalogPackage(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRuleCatalogPackage(ctx context.Context, catalogID int64, packageID string) (model.RuleCatalogPackage, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, catalog_id, package_id, name, version, compatibility, checksum,
			signature_key_id, signature_checksum, signature_value, signature_expires_at, signature_status,
			updated_at_text, manifest_url, package_json, source_identity, sync_status, stale, last_synced_at, created_at, updated_at
		FROM rule_catalog_packages
		WHERE catalog_id = $1 AND package_id = $2`, catalogID, packageID)
	item, err := scanRuleCatalogPackage(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleCatalogPackage{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) ReplaceRuleCatalogPackages(ctx context.Context, catalogID int64, items []model.RuleCatalogPackage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM rule_catalog_sources WHERE id = $1)`, catalogID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM rule_catalog_packages WHERE catalog_id = $1`, catalogID); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO rule_catalog_packages (
				catalog_id, package_id, name, version, compatibility, checksum,
				signature_key_id, signature_checksum, signature_value, signature_expires_at, signature_status,
				updated_at_text, manifest_url, package_json, source_identity, sync_status, stale, last_synced_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
			catalogID, item.PackageID, item.Name, item.Version, item.Compatibility, item.Checksum,
			item.Signature.KeyID, item.Signature.Checksum, item.Signature.Signature, item.Signature.ExpiresAt, item.SignatureStatus,
			item.UpdatedAtText, item.ManifestURL, item.PackageJSON, item.SourceIdentity, item.SyncStatus, item.Stale, nullableTime(item.LastSyncedAt)); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rule_catalog_sources SET status = 'synced', last_sync_at = now(), last_error = '', updated_at = now() WHERE id = $1`, catalogID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) ListRuleTrustKeys(ctx context.Context) ([]model.RuleTrustKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, key_id, algorithm, owner, enabled, revoked, expires_at, created_at, updated_at
		FROM rule_trust_keys
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleTrustKey
	for rows.Next() {
		var item model.RuleTrustKey
		var expires sql.NullTime
		if err := rows.Scan(&item.ID, &item.KeyID, &item.Algorithm, &item.Owner, &item.Enabled, &item.Revoked, &expires, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if expires.Valid {
			item.ExpiresAt = expires.Time
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRuleTrustKey(ctx context.Context, keyID string) (model.RuleTrustKey, error) {
	var item model.RuleTrustKey
	var expires sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, key_id, algorithm, owner, public_key, enabled, revoked, expires_at, created_at, updated_at
		FROM rule_trust_keys
		WHERE key_id = $1`, keyID).
		Scan(&item.ID, &item.KeyID, &item.Algorithm, &item.Owner, &item.PublicKey, &item.Enabled, &item.Revoked, &expires, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleTrustKey{}, ErrNotFound
	}
	if expires.Valid {
		item.ExpiresAt = expires.Time
	}
	return item, err
}

func (s *PostgresStore) CreateRuleTrustKey(ctx context.Context, item model.RuleTrustKey) (model.RuleTrustKey, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rule_trust_keys (key_id, algorithm, owner, public_key, enabled, revoked, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`,
		item.KeyID, item.Algorithm, item.Owner, item.PublicKey, item.Enabled, item.Revoked, nullableTime(item.ExpiresAt)).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	item.PublicKey = ""
	return item, err
}

func (s *PostgresStore) UpdateRuleTrustKey(ctx context.Context, id int64, item model.RuleTrustKey) (model.RuleTrustKey, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE rule_trust_keys
		SET key_id = $2, algorithm = $3, owner = $4, public_key = CASE WHEN $5 = '' THEN public_key ELSE $5 END,
			enabled = $6, revoked = $7, expires_at = $8, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.KeyID, item.Algorithm, item.Owner, item.PublicKey, item.Enabled, item.Revoked, nullableTime(item.ExpiresAt)).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleTrustKey{}, ErrNotFound
	}
	item.PublicKey = ""
	return item, err
}

type catalogPackageScanner interface {
	Scan(dest ...any) error
}

func scanRuleCatalogPackage(row catalogPackageScanner) (model.RuleCatalogPackage, error) {
	var item model.RuleCatalogPackage
	var lastSynced sql.NullTime
	err := row.Scan(
		&item.ID, &item.CatalogID, &item.PackageID, &item.Name, &item.Version, &item.Compatibility, &item.Checksum,
		&item.Signature.KeyID, &item.Signature.Checksum, &item.Signature.Signature, &item.Signature.ExpiresAt, &item.SignatureStatus,
		&item.UpdatedAtText, &item.ManifestURL, &item.PackageJSON, &item.SourceIdentity, &item.SyncStatus, &item.Stale, &lastSynced, &item.CreatedAt, &item.UpdatedAt,
	)
	if lastSynced.Valid {
		item.LastSyncedAt = lastSynced.Time
	}
	return item, err
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

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
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

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func joinCSV(values []string) string {
	if len(values) == 0 {
		return ""
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item != "" {
			out = append(out, item)
		}
	}
	return strings.Join(out, ",")
}
