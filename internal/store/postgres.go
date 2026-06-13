package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
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

func (s *PostgresStore) ListApplications(ctx context.Context) ([]model.Application, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, mode, enabled, description, proxy_config_json, created_at, updated_at
		FROM applications
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.Application
	for rows.Next() {
		var item model.Application
		var proxyConfigJSON string
		if err := rows.Scan(&item.ID, &item.Name, &item.Mode, &item.Enabled, &item.Description, &proxyConfigJSON, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if item.ProxyConfig, err = decodeApplicationProxyConfig(proxyConfigJSON); err != nil {
			return nil, err
		}
		if err := s.loadApplicationChildren(ctx, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetApplication(ctx context.Context, id int64) (model.Application, error) {
	var item model.Application
	var proxyConfigJSON string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, mode, enabled, description, proxy_config_json, created_at, updated_at
		FROM applications
		WHERE id = $1`, id).
		Scan(&item.ID, &item.Name, &item.Mode, &item.Enabled, &item.Description, &proxyConfigJSON, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Application{}, ErrNotFound
	}
	if err != nil {
		return model.Application{}, err
	}
	if item.ProxyConfig, err = decodeApplicationProxyConfig(proxyConfigJSON); err != nil {
		return model.Application{}, err
	}
	if err := s.loadApplicationChildren(ctx, &item); err != nil {
		return model.Application{}, err
	}
	return item, nil
}

func (s *PostgresStore) CreateApplication(ctx context.Context, item model.Application) (model.Application, error) {
	model.NormalizeApplication(&item)
	if err := model.ValidateApplication(item, func(id int64) bool {
		ok, err := s.certificateExists(ctx, id)
		return err == nil && ok
	}); err != nil {
		return model.Application{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Application{}, err
	}
	defer tx.Rollback()
	proxyConfigJSON, err := encodeApplicationProxyConfig(item.ProxyConfig)
	if err != nil {
		return model.Application{}, err
	}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO applications (name, mode, enabled, description, proxy_config_json)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Mode, item.Enabled, item.Description, proxyConfigJSON).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return model.Application{}, err
	}
	if err := replaceApplicationChildren(ctx, tx, &item); err != nil {
		return model.Application{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.Application{}, err
	}
	return s.GetApplication(ctx, item.ID)
}

func (s *PostgresStore) UpdateApplication(ctx context.Context, id int64, item model.Application) (model.Application, error) {
	model.NormalizeApplication(&item)
	if err := model.ValidateApplication(item, func(certID int64) bool {
		ok, err := s.certificateExists(ctx, certID)
		return err == nil && ok
	}); err != nil {
		return model.Application{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Application{}, err
	}
	defer tx.Rollback()
	proxyConfigJSON, err := encodeApplicationProxyConfig(item.ProxyConfig)
	if err != nil {
		return model.Application{}, err
	}
	err = tx.QueryRowContext(ctx, `
		UPDATE applications
		SET name = $2, mode = $3, enabled = $4, description = $5, proxy_config_json = $6, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Mode, item.Enabled, item.Description, proxyConfigJSON).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Application{}, ErrNotFound
	}
	if err != nil {
		return model.Application{}, err
	}
	item.ID = id
	if _, err := tx.ExecContext(ctx, `DELETE FROM application_hosts WHERE application_id = $1`, id); err != nil {
		return model.Application{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM application_listeners WHERE application_id = $1`, id); err != nil {
		return model.Application{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM application_upstreams WHERE application_id = $1`, id); err != nil {
		return model.Application{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM application_routes WHERE application_id = $1`, id); err != nil {
		return model.Application{}, err
	}
	if err := replaceApplicationChildren(ctx, tx, &item); err != nil {
		return model.Application{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.Application{}, err
	}
	return s.GetApplication(ctx, id)
}

func (s *PostgresStore) DeleteApplication(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM applications WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) ListCertificates(ctx context.Context) ([]model.Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, domains, cert_pem, key_pem, not_before, not_after, fingerprint, created_at, updated_at
		FROM certificates
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.Certificate
	for rows.Next() {
		item, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetCertificate(ctx context.Context, id int64) (model.Certificate, error) {
	item, err := scanCertificate(s.db.QueryRowContext(ctx, `
		SELECT id, name, domains, cert_pem, key_pem, not_before, not_after, fingerprint, created_at, updated_at
		FROM certificates
		WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Certificate{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateCertificate(ctx context.Context, item model.Certificate) (model.Certificate, error) {
	if err := model.ValidateCertificate(item); err != nil {
		return model.Certificate{}, err
	}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO certificates (name, domains, cert_pem, key_pem, not_before, not_after, fingerprint)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`,
		item.Name, joinCSV(item.Domains), item.CertPEM, item.KeyPEM, item.NotBefore, item.NotAfter, item.Fingerprint).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) DeleteCertificate(ctx context.Context, id int64) error {
	inUse, err := s.CertificateInUse(ctx, id)
	if err != nil {
		return err
	}
	if inUse {
		return errors.New("certificate is used by enabled application listeners")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM certificates WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) CertificateInUse(ctx context.Context, id int64) (bool, error) {
	exists, err := s.certificateExists(ctx, id)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, ErrNotFound
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM application_listeners
		WHERE certificate_id = $1 AND enabled = true`, id).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *PostgresStore) ListRules(ctx context.Context) ([]model.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, type, target, action, expression, score, enabled, module, category, attack_type, group_name, priority,
			package_id, package_version, package_rule_id, source_checksum, signature_status, review_status, last_test_status,
			remote_catalog_id, provider_id, provider_name, provider_package_ref, last_synced_version, pending_update_state, local_override_state, export_eligible, export_ineligible_reasons,
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
			&item.RemoteCatalogID, &item.ProviderID, &item.ProviderName, &item.ProviderPackageRef, &item.LastSyncedVersion, &item.PendingUpdateState, &item.LocalOverrideState, &item.ExportEligible, &exportReasons,
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
			remote_catalog_id, provider_id, provider_name, provider_package_ref, last_synced_version, pending_update_state, local_override_state, export_eligible, export_ineligible_reasons,
			created_at, updated_at
		FROM rules
		WHERE id = $1`, id).
		Scan(
			&item.ID, &item.Name, &item.Type, &item.Target, &item.Action, &item.Expression, &item.Score,
			&item.Enabled, &item.Module, &item.Category, &item.AttackType, &item.Group, &item.Priority,
			&item.PackageID, &item.PackageVersion, &item.PackageRuleID, &item.SourceChecksum,
			&item.SignatureStatus, &item.ReviewStatus, &item.LastTestStatus,
			&item.RemoteCatalogID, &item.ProviderID, &item.ProviderName, &item.ProviderPackageRef, &item.LastSyncedVersion, &item.PendingUpdateState, &item.LocalOverrideState, &item.ExportEligible, &exportReasons,
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
			remote_catalog_id, provider_id, provider_name, provider_package_ref, last_synced_version, pending_update_state, local_override_state, export_eligible, export_ineligible_reasons
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
		RETURNING id, created_at, updated_at`,
		rule.Name, rule.Type, rule.Target, rule.Action, rule.Expression, rule.Score, rule.Enabled,
		rule.Module, rule.Category, rule.AttackType, rule.Group, rule.Priority,
		rule.PackageID, rule.PackageVersion, rule.PackageRuleID, rule.SourceChecksum,
		rule.SignatureStatus, rule.ReviewStatus, rule.LastTestStatus,
		rule.RemoteCatalogID, rule.ProviderID, rule.ProviderName, rule.ProviderPackageRef, rule.LastSyncedVersion, rule.PendingUpdateState, rule.LocalOverrideState, rule.ExportEligible, joinCSV(rule.ExportIneligibleReasons)).
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
			remote_catalog_id = $21, provider_id = $22, provider_name = $23, provider_package_ref = $24,
			last_synced_version = $25, pending_update_state = $26,
			local_override_state = $27, export_eligible = $28, export_ineligible_reasons = $29, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, rule.Name, rule.Type, rule.Target, rule.Action, rule.Expression, rule.Score, rule.Enabled,
		rule.Module, rule.Category, rule.AttackType, rule.Group, rule.Priority,
		rule.PackageID, rule.PackageVersion, rule.PackageRuleID, rule.SourceChecksum,
		rule.SignatureStatus, rule.ReviewStatus, rule.LastTestStatus,
		rule.RemoteCatalogID, rule.ProviderID, rule.ProviderName, rule.ProviderPackageRef, rule.LastSyncedVersion, rule.PendingUpdateState, rule.LocalOverrideState, rule.ExportEligible, joinCSV(rule.ExportIneligibleReasons)).
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

	if err := validateApplicationRefs(ctx, tx, policy.SiteIDs); err != nil {
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

	if err := validateApplicationRefs(ctx, tx, policy.SiteIDs); err != nil {
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
		SELECT id, version, operator, status, config_path, checksum, note, config_json, runtime_artifacts_json, created_at
		FROM publish_records
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.PublishRecord
	for rows.Next() {
		var item model.PublishRecord
		if err := rows.Scan(&item.ID, &item.Version, &item.Operator, &item.Status, &item.ConfigPath, &item.Checksum, &item.Note, &item.ConfigJSON, &item.RuntimeArtifactsJSON, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, model.AttachPublishActivation(item))
	}
	return items, rows.Err()
}

func (s *PostgresStore) CreatePublishRecord(ctx context.Context, record model.PublishRecord) (model.PublishRecord, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO publish_records (version, operator, status, config_path, checksum, note, config_json, runtime_artifacts_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at`,
		record.Version, record.Operator, record.Status, record.ConfigPath, record.Checksum, record.Note, record.ConfigJSON, record.RuntimeArtifactsJSON).
		Scan(&record.ID, &record.CreatedAt)
	record.Time = record.CreatedAt.Format(time.RFC3339)
	record = model.AttachPublishActivation(record)
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
		SELECT id, version, operator, status, config_path, checksum, note, config_json, runtime_artifacts_json, created_at
		FROM publish_records
		WHERE version = $1`, version).
		Scan(&item.ID, &item.Version, &item.Operator, &item.Status, &item.ConfigPath, &item.Checksum, &item.Note, &item.ConfigJSON, &item.RuntimeArtifactsJSON, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.PublishRecord{}, ErrNotFound
	}
	item.Time = item.CreatedAt.Format(time.RFC3339)
	return model.AttachPublishActivation(item), err
}

func (s *PostgresStore) GetNginxConfigDraft(ctx context.Context) (model.NginxConfigDraft, error) {
	var draft model.NginxConfigDraft
	var snippetsJSON string
	var validationJSON string
	var publishedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT mode, snippets_json, full_config, validation_json, updated_by, updated_at, published_at
		FROM nginx_config_drafts
		WHERE id = 1`).
		Scan(&draft.Mode, &snippetsJSON, &draft.FullConfig, &validationJSON, &draft.UpdatedBy, &draft.UpdatedAt, &publishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.EmptyNginxConfigDraft(), nil
	}
	if err != nil {
		return model.NginxConfigDraft{}, err
	}
	if snippetsJSON != "" {
		if err := json.Unmarshal([]byte(snippetsJSON), &draft.Snippets); err != nil {
			return model.NginxConfigDraft{}, err
		}
	}
	if validationJSON != "" {
		if err := json.Unmarshal([]byte(validationJSON), &draft.Validation); err != nil {
			return model.NginxConfigDraft{}, err
		}
	}
	if publishedAt.Valid {
		draft.PublishedAt = &publishedAt.Time
	}
	model.NormalizeNginxConfigDraft(&draft)
	return draft, nil
}

func (s *PostgresStore) SaveNginxConfigDraft(ctx context.Context, draft model.NginxConfigDraft) (model.NginxConfigDraft, error) {
	model.NormalizeNginxConfigDraft(&draft)
	if err := model.ValidateNginxConfigDraft(draft); err != nil {
		return model.NginxConfigDraft{}, err
	}
	snippetsJSON, err := json.Marshal(draft.Snippets)
	if err != nil {
		return model.NginxConfigDraft{}, err
	}
	validationJSON, err := json.Marshal(draft.Validation)
	if err != nil {
		return model.NginxConfigDraft{}, err
	}
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO nginx_config_drafts (id, mode, snippets_json, full_config, validation_json, updated_by, updated_at, published_at)
		VALUES (1, $1, $2, $3, $4, $5, now(), $6)
		ON CONFLICT (id) DO UPDATE
		SET mode = EXCLUDED.mode,
			snippets_json = EXCLUDED.snippets_json,
			full_config = EXCLUDED.full_config,
			validation_json = EXCLUDED.validation_json,
			updated_by = EXCLUDED.updated_by,
			updated_at = now(),
			published_at = EXCLUDED.published_at
		RETURNING updated_at`,
		draft.Mode, string(snippetsJSON), draft.FullConfig, string(validationJSON), draft.UpdatedBy, draft.PublishedAt).
		Scan(&draft.UpdatedAt)
	if err != nil {
		return model.NginxConfigDraft{}, err
	}
	return draft, nil
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

func (s *PostgresStore) ListAuditLogs(ctx context.Context, filter model.AuditLogFilter) (model.ListResult[model.AuditLog], error) {
	pagination := normalizePagination(filter.Pagination)
	var total int
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM audit_logs
		WHERE ($1 = '' OR actor = $1)
			AND ($2 = '' OR action = $2)
			AND ($3 = '' OR resource_type = $3)
			AND ($4 = '' OR result = $4)
			AND ($5::timestamptz IS NULL OR created_at >= $5)
			AND ($6::timestamptz IS NULL OR created_at <= $6)`,
		filter.Actor, filter.Action, filter.ResourceType, filter.Result, nullableTime(filter.Since), nullableTime(filter.Until)).Scan(&total); err != nil {
		return model.ListResult[model.AuditLog]{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, actor, role, action, resource_type, resource_id, result, remote_addr, user_agent, message, created_at
		FROM audit_logs
		WHERE ($1 = '' OR actor = $1)
			AND ($2 = '' OR action = $2)
			AND ($3 = '' OR resource_type = $3)
			AND ($4 = '' OR result = $4)
			AND ($5::timestamptz IS NULL OR created_at >= $5)
			AND ($6::timestamptz IS NULL OR created_at <= $6)
		ORDER BY id DESC
		LIMIT $7 OFFSET $8`,
		filter.Actor, filter.Action, filter.ResourceType, filter.Result, nullableTime(filter.Since), nullableTime(filter.Until), pagination.Limit, pagination.Offset)
	if err != nil {
		return model.ListResult[model.AuditLog]{}, err
	}
	defer rows.Close()
	var items []model.AuditLog
	for rows.Next() {
		var item model.AuditLog
		if err := rows.Scan(&item.ID, &item.Actor, &item.Role, &item.Action, &item.ResourceType, &item.ResourceID, &item.Result, &item.RemoteAddr, &item.UserAgent, &item.Message, &item.CreatedAt); err != nil {
			return model.ListResult[model.AuditLog]{}, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return model.ListResult[model.AuditLog]{Items: items, Total: total, Pagination: pagination}, rows.Err()
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

func (s *PostgresStore) ListIPAccessListEntries(ctx context.Context) ([]model.IPAccessListEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, kind, target, value, normalized_value, ip_family, prefix_length, site_id, enabled, priority, conflict_key, description, created_at, updated_at
		FROM ip_access_list_entries
		ORDER BY priority, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.IPAccessListEntry
	for rows.Next() {
		var item model.IPAccessListEntry
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.Target, &item.Value, &item.NormalizedValue, &item.IPFamily, &item.PrefixLength, &item.SiteID, &item.Enabled, &item.Priority, &item.ConflictKey, &item.Description, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetIPAccessListEntry(ctx context.Context, id int64) (model.IPAccessListEntry, error) {
	var item model.IPAccessListEntry
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, kind, target, value, normalized_value, ip_family, prefix_length, site_id, enabled, priority, conflict_key, description, created_at, updated_at
		FROM ip_access_list_entries
		WHERE id = $1`, id).
		Scan(&item.ID, &item.Name, &item.Kind, &item.Target, &item.Value, &item.NormalizedValue, &item.IPFamily, &item.PrefixLength, &item.SiteID, &item.Enabled, &item.Priority, &item.ConflictKey, &item.Description, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.IPAccessListEntry{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateIPAccessListEntry(ctx context.Context, item model.IPAccessListEntry) (model.IPAccessListEntry, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO ip_access_list_entries (name, kind, target, value, normalized_value, ip_family, prefix_length, site_id, enabled, priority, conflict_key, description)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Kind, item.Target, item.Value, item.NormalizedValue, item.IPFamily, item.PrefixLength, item.SiteID, item.Enabled, item.Priority, item.ConflictKey, item.Description).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateIPAccessListEntry(ctx context.Context, id int64, item model.IPAccessListEntry) (model.IPAccessListEntry, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE ip_access_list_entries
		SET name = $2, kind = $3, target = $4, value = $5, normalized_value = $6, ip_family = $7, prefix_length = $8, site_id = $9, enabled = $10, priority = $11, conflict_key = $12, description = $13, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Kind, item.Target, item.Value, item.NormalizedValue, item.IPFamily, item.PrefixLength, item.SiteID, item.Enabled, item.Priority, item.ConflictKey, item.Description).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.IPAccessListEntry{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) DeleteIPAccessListEntry(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM ip_access_list_entries WHERE id = $1`, id)
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

func (s *PostgresStore) ListProtectionRules(ctx context.Context) ([]model.ProtectionRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, module, category, site_id, enabled, priority,
			match_json, limit_json, upload_json, challenge_json, dynamic_json, action_json,
			source, migration_status, legacy_ref, created_at, updated_at
		FROM protection_rules
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.ProtectionRule
	for rows.Next() {
		item, err := scanProtectionRule(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetProtectionRule(ctx context.Context, id int64) (model.ProtectionRule, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, module, category, site_id, enabled, priority,
			match_json, limit_json, upload_json, challenge_json, dynamic_json, action_json,
			source, migration_status, legacy_ref, created_at, updated_at
		FROM protection_rules
		WHERE id = $1`, id)
	item, err := scanProtectionRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ProtectionRule{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateProtectionRule(ctx context.Context, item model.ProtectionRule) (model.ProtectionRule, error) {
	item = protectionrules.Normalize(item)
	if err := protectionrules.Validate(item); err != nil {
		return model.ProtectionRule{}, err
	}
	encoded, err := encodeProtectionRule(item)
	if err != nil {
		return model.ProtectionRule{}, err
	}
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO protection_rules (
			name, module, category, site_id, enabled, priority,
			match_json, limit_json, upload_json, challenge_json, dynamic_json, action_json,
			source, migration_status, legacy_ref
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Module, item.Category, item.SiteID, item.Enabled, item.Priority,
		encoded.Match, encoded.Limit, encoded.Upload, encoded.Challenge, encoded.Dynamic, encoded.Action,
		item.Source, item.MigrationStatus, item.LegacyRef).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateProtectionRule(ctx context.Context, id int64, item model.ProtectionRule) (model.ProtectionRule, error) {
	item = protectionrules.Normalize(item)
	if err := protectionrules.Validate(item); err != nil {
		return model.ProtectionRule{}, err
	}
	encoded, err := encodeProtectionRule(item)
	if err != nil {
		return model.ProtectionRule{}, err
	}
	err = s.db.QueryRowContext(ctx, `
		UPDATE protection_rules
		SET name = $2, module = $3, category = $4, site_id = $5, enabled = $6, priority = $7,
			match_json = $8, limit_json = $9, upload_json = $10, challenge_json = $11,
			dynamic_json = $12, action_json = $13, source = $14, migration_status = $15,
			legacy_ref = $16, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Module, item.Category, item.SiteID, item.Enabled, item.Priority,
		encoded.Match, encoded.Limit, encoded.Upload, encoded.Challenge, encoded.Dynamic, encoded.Action,
		item.Source, item.MigrationStatus, item.LegacyRef).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ProtectionRule{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) DeleteProtectionRule(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM protection_rules WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) BackfillProtectionRules(ctx context.Context) (int, error) {
	var candidates []model.ProtectionRule
	rateLimits, err := s.ListRateLimitRules(ctx)
	if err != nil {
		return 0, err
	}
	for _, item := range rateLimits {
		candidates = append(candidates, protectionrules.FromRateLimit(item))
	}
	uploadRules, err := s.ListUploadProtectionRules(ctx)
	if err != nil {
		return 0, err
	}
	for _, item := range uploadRules {
		candidates = append(candidates, protectionrules.FromUpload(item))
	}
	botRules, err := s.ListBotProtectionRules(ctx)
	if err != nil {
		return 0, err
	}
	for _, item := range botRules {
		candidates = append(candidates, protectionrules.FromBot(item))
	}
	dynamicRules, err := s.ListDynamicProtectionRules(ctx)
	if err != nil {
		return 0, err
	}
	for _, item := range dynamicRules {
		candidates = append(candidates, protectionrules.FromDynamic(item))
	}
	rules, err := s.ListRules(ctx)
	if err != nil {
		return 0, err
	}
	for _, raw := range rules {
		rule := attackmeta.NormalizeRule(raw)
		if rule.Module == attackmeta.Module && rule.Category == attackmeta.Category {
			candidates = append(candidates, protectionrules.FromAttackRule(rule))
		}
	}
	created := 0
	for _, item := range candidates {
		item = protectionrules.Normalize(item)
		item.ID = 0
		item.Source = protectionrules.SourceLegacy
		item.MigrationStatus = protectionrules.StatusMigrated
		if err := protectionrules.Validate(item); err != nil {
			return created, err
		}
		encoded, err := encodeProtectionRule(item)
		if err != nil {
			return created, err
		}
		result, err := s.db.ExecContext(ctx, `
			INSERT INTO protection_rules (
				name, module, category, site_id, enabled, priority,
				match_json, limit_json, upload_json, challenge_json, dynamic_json, action_json,
				source, migration_status, legacy_ref
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			ON CONFLICT (legacy_ref) WHERE legacy_ref <> '' DO NOTHING`,
			item.Name, item.Module, item.Category, item.SiteID, item.Enabled, item.Priority,
			encoded.Match, encoded.Limit, encoded.Upload, encoded.Challenge, encoded.Dynamic, encoded.Action,
			item.Source, item.MigrationStatus, item.LegacyRef)
		if err != nil {
			return created, err
		}
		if rows, err := result.RowsAffected(); err == nil && rows > 0 {
			created++
		}
	}
	return created, nil
}

func (s *PostgresStore) ListRuleCatalogSources(ctx context.Context) ([]model.RuleCatalogSource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.name, s.source, s.provider_id, COALESCE(pa.name, ''), COALESCE(pa.health_status, ''),
			s.enabled, s.timeout_sec, s.status, s.last_sync_at, s.last_error, count(p.id), s.created_at, s.updated_at
		FROM rule_catalog_sources s
		LEFT JOIN rule_catalog_packages p ON p.catalog_id = s.id
		LEFT JOIN rule_provider_adapters pa ON pa.id = s.provider_id
		GROUP BY s.id, pa.name, pa.health_status
		ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleCatalogSource
	for rows.Next() {
		var item model.RuleCatalogSource
		var lastSync sql.NullTime
		if err := rows.Scan(&item.ID, &item.Name, &item.Source, &item.ProviderID, &item.ProviderName, &item.ProviderHealth, &item.Enabled, &item.TimeoutSec, &item.Status, &lastSync, &item.LastError, &item.PackageCount, &item.CreatedAt, &item.UpdatedAt); err != nil {
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
		SELECT s.id, s.name, s.source, s.provider_id, COALESCE(pa.name, ''), COALESCE(pa.health_status, ''),
			s.enabled, s.timeout_sec, s.status, s.last_sync_at, s.last_error, count(p.id), s.created_at, s.updated_at
		FROM rule_catalog_sources s
		LEFT JOIN rule_catalog_packages p ON p.catalog_id = s.id
		LEFT JOIN rule_provider_adapters pa ON pa.id = s.provider_id
		WHERE s.id = $1
		GROUP BY s.id, pa.name, pa.health_status`, id).
		Scan(&item.ID, &item.Name, &item.Source, &item.ProviderID, &item.ProviderName, &item.ProviderHealth, &item.Enabled, &item.TimeoutSec, &item.Status, &lastSync, &item.LastError, &item.PackageCount, &item.CreatedAt, &item.UpdatedAt)
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
		INSERT INTO rule_catalog_sources (name, source, provider_id, enabled, timeout_sec, status, last_error)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Source, item.ProviderID, item.Enabled, item.TimeoutSec, item.Status, item.LastError).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateRuleCatalogSource(ctx context.Context, id int64, item model.RuleCatalogSource) (model.RuleCatalogSource, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE rule_catalog_sources
		SET name = $2, source = $3, provider_id = $4, enabled = $5, timeout_sec = $6, status = $7, last_sync_at = $8, last_error = $9, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.Source, item.ProviderID, item.Enabled, item.TimeoutSec, item.Status, nullableTime(item.LastSyncAt), item.LastError).
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
		SELECT id, catalog_id, provider_id, provider_name, provider_package_ref, entitlement_state, package_id, name, version, compatibility, checksum,
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
		SELECT id, catalog_id, provider_id, provider_name, provider_package_ref, entitlement_state, package_id, name, version, compatibility, checksum,
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
				catalog_id, provider_id, provider_name, provider_package_ref, entitlement_state, package_id, name, version, compatibility, checksum,
				signature_key_id, signature_checksum, signature_value, signature_expires_at, signature_status,
				updated_at_text, manifest_url, package_json, source_identity, sync_status, stale, last_synced_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)`,
			catalogID, item.ProviderID, item.ProviderName, item.ProviderPackageRef, item.EntitlementState, item.PackageID, item.Name, item.Version, item.Compatibility, item.Checksum,
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

func (s *PostgresStore) ListRuleProviderAdapters(ctx context.Context) ([]model.RuleProviderAdapter, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.name, p.provider_type, p.endpoint, p.auth_mode, p.enabled, p.timeout_sec,
			p.retry_max_attempts, p.retry_backoff_sec,
			p.credential_alias, p.credential_fingerprint, p.credential_last_four, p.credential_expires_at, p.credential_last_validated_at, p.credential_status,
			p.health_status, p.sync_status, p.last_sync_at, p.last_failed_sync_at, p.last_error, p.attempt_count, p.next_retry_at, p.retry_exhausted,
			count(pkg.id), p.created_at, p.updated_at
		FROM rule_provider_adapters p
		LEFT JOIN rule_provider_packages pkg ON pkg.provider_id = p.id
		GROUP BY p.id
		ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleProviderAdapter
	for rows.Next() {
		item, err := scanRuleProviderAdapter(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRuleProviderAdapter(ctx context.Context, id int64) (model.RuleProviderAdapter, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT p.id, p.name, p.provider_type, p.endpoint, p.auth_mode, p.enabled, p.timeout_sec,
			p.retry_max_attempts, p.retry_backoff_sec,
			p.credential_alias, p.credential_fingerprint, p.credential_last_four, p.credential_expires_at, p.credential_last_validated_at, p.credential_status,
			p.health_status, p.sync_status, p.last_sync_at, p.last_failed_sync_at, p.last_error, p.attempt_count, p.next_retry_at, p.retry_exhausted,
			count(pkg.id), p.created_at, p.updated_at
		FROM rule_provider_adapters p
		LEFT JOIN rule_provider_packages pkg ON pkg.provider_id = p.id
		WHERE p.id = $1
		GROUP BY p.id`, id)
	item, err := scanRuleProviderAdapter(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleProviderAdapter{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateRuleProviderAdapter(ctx context.Context, item model.RuleProviderAdapter, secret model.RuleCommunityAccountSecret) (model.RuleProviderAdapter, error) {
	item.Credential = postgresRedactCredential(item.Credential, secret.Secret, time.Now().UTC())
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rule_provider_adapters (
			name, provider_type, endpoint, auth_mode, enabled, timeout_sec, retry_max_attempts, retry_backoff_sec,
			credential_alias, credential_fingerprint, credential_last_four, credential_expires_at, credential_last_validated_at, credential_status, credential_secret,
			health_status, sync_status, last_error, attempt_count, retry_exhausted
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		RETURNING id, created_at, updated_at`,
		item.Name, item.ProviderType, item.Endpoint, item.AuthMode, item.Enabled, item.TimeoutSec, item.RetryPolicy.MaxAttempts, item.RetryPolicy.BackoffSec,
		item.Credential.Alias, item.Credential.Fingerprint, item.Credential.LastFour, nullableTime(item.Credential.ExpiresAt), nullableTime(item.Credential.LastValidatedAt), item.Credential.Status, secret.Secret,
		item.HealthStatus, item.SyncStatus, item.LastError, item.AttemptCount, item.RetryExhausted).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateRuleProviderAdapter(ctx context.Context, id int64, item model.RuleProviderAdapter, secret model.RuleCommunityAccountSecret) (model.RuleProviderAdapter, error) {
	existing, err := s.GetRuleProviderAdapter(ctx, id)
	if err != nil {
		return model.RuleProviderAdapter{}, err
	}
	if secret.Secret == "" {
		item.Credential = existing.Credential
	} else {
		item.Credential = postgresRedactCredential(item.Credential, secret.Secret, time.Now().UTC())
	}
	err = s.db.QueryRowContext(ctx, `
		UPDATE rule_provider_adapters
		SET name = $2, provider_type = $3, endpoint = $4, auth_mode = $5, enabled = $6, timeout_sec = $7,
			retry_max_attempts = $8, retry_backoff_sec = $9,
			credential_alias = $10, credential_fingerprint = $11, credential_last_four = $12,
			credential_expires_at = $13, credential_last_validated_at = $14, credential_status = $15,
			credential_secret = CASE WHEN $16 = '' THEN credential_secret ELSE $16 END,
			health_status = $17, sync_status = $18, last_error = $19, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.ProviderType, item.Endpoint, item.AuthMode, item.Enabled, item.TimeoutSec,
		item.RetryPolicy.MaxAttempts, item.RetryPolicy.BackoffSec,
		item.Credential.Alias, item.Credential.Fingerprint, item.Credential.LastFour,
		nullableTime(item.Credential.ExpiresAt), nullableTime(item.Credential.LastValidatedAt), item.Credential.Status, secret.Secret,
		item.HealthStatus, item.SyncStatus, item.LastError).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleProviderAdapter{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) DeleteRuleProviderAdapter(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM rule_provider_adapters WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) UpdateRuleProviderSyncState(ctx context.Context, id int64, item model.RuleProviderAdapter, packages []model.RuleProviderPackage) (model.RuleProviderAdapter, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.RuleProviderAdapter{}, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `
		UPDATE rule_provider_adapters
		SET health_status = $2, sync_status = $3, last_sync_at = $4, last_failed_sync_at = $5, last_error = $6,
			attempt_count = $7, next_retry_at = $8, retry_exhausted = $9, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.HealthStatus, item.SyncStatus, nullableTime(item.LastSyncAt), nullableTime(item.LastFailedSyncAt), item.LastError,
		item.AttemptCount, nullableTime(item.NextRetryAt), item.RetryExhausted).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleProviderAdapter{}, ErrNotFound
	}
	if err != nil {
		return model.RuleProviderAdapter{}, err
	}
	if packages != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM rule_provider_packages WHERE provider_id = $1`, id); err != nil {
			return model.RuleProviderAdapter{}, err
		}
		for _, pkg := range packages {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO rule_provider_packages (
					provider_id, provider_package_ref, package_id, name, version, compatibility, checksum,
					signature_key_id, signature_checksum, signature_value, signature_expires_at, signature_status,
					updated_at_text, manifest_url, package_json, source_identity, entitlement_state, sync_status, stale, last_synced_at
				)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
				id, pkg.ProviderPackageRef, pkg.PackageID, pkg.Name, pkg.Version, pkg.Compatibility, pkg.Checksum,
				pkg.Signature.KeyID, pkg.Signature.Checksum, pkg.Signature.Signature, pkg.Signature.ExpiresAt, pkg.SignatureStatus,
				pkg.UpdatedAtText, pkg.ManifestURL, pkg.PackageJSON, pkg.SourceIdentity, pkg.EntitlementState, pkg.SyncStatus, pkg.Stale, nullableTime(pkg.LastSyncedAt)); err != nil {
				return model.RuleProviderAdapter{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return model.RuleProviderAdapter{}, err
	}
	return s.GetRuleProviderAdapter(ctx, id)
}

func (s *PostgresStore) ListRuleProviderPackages(ctx context.Context, providerID int64) ([]model.RuleProviderPackage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT pkg.id, pkg.provider_id, p.name, p.provider_type, pkg.provider_package_ref, pkg.package_id, pkg.name, pkg.version, pkg.compatibility, pkg.checksum,
			pkg.signature_key_id, pkg.signature_checksum, pkg.signature_value, pkg.signature_expires_at, pkg.signature_status,
			pkg.updated_at_text, pkg.manifest_url, pkg.package_json, pkg.source_identity, pkg.entitlement_state, pkg.sync_status, pkg.stale, pkg.last_synced_at, pkg.created_at, pkg.updated_at
		FROM rule_provider_packages pkg
		JOIN rule_provider_adapters p ON p.id = pkg.provider_id
		WHERE ($1 = 0 OR pkg.provider_id = $1)
		ORDER BY pkg.provider_id, pkg.package_id`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleProviderPackage
	for rows.Next() {
		item, err := scanRuleProviderPackage(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRuleProviderPackage(ctx context.Context, providerID int64, packageID string) (model.RuleProviderPackage, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT pkg.id, pkg.provider_id, p.name, p.provider_type, pkg.provider_package_ref, pkg.package_id, pkg.name, pkg.version, pkg.compatibility, pkg.checksum,
			pkg.signature_key_id, pkg.signature_checksum, pkg.signature_value, pkg.signature_expires_at, pkg.signature_status,
			pkg.updated_at_text, pkg.manifest_url, pkg.package_json, pkg.source_identity, pkg.entitlement_state, pkg.sync_status, pkg.stale, pkg.last_synced_at, pkg.created_at, pkg.updated_at
		FROM rule_provider_packages pkg
		JOIN rule_provider_adapters p ON p.id = pkg.provider_id
		WHERE pkg.provider_id = $1 AND (pkg.package_id = $2 OR pkg.provider_package_ref = $2)`, providerID, packageID)
	item, err := scanRuleProviderPackage(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleProviderPackage{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) ListRuleCommunityAccountSources(ctx context.Context) ([]model.RuleCommunityAccountSource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.name, s.provider_type, s.provider_adapter_id, COALESCE(p.name, ''), COALESCE(p.health_status, ''),
			CASE WHEN COALESCE(p.retry_exhausted, false) THEN 'exhausted' WHEN COALESCE(p.attempt_count, 0) > 0 THEN 'retrying' ELSE 'ready' END,
			s.endpoint, s.enabled, s.timeout_sec,
			s.credential_alias, s.credential_fingerprint, s.credential_last_four, s.credential_expires_at, s.credential_last_validated_at, s.credential_status,
			s.subscription_status, s.entitlement_summary, s.package_count, s.status, s.last_sync_at, s.last_error,
			(SELECT count(*) FROM rule_review_queue q WHERE q.source_identity = 'account:' || s.id AND q.state = 'queued') AS recommendation_count,
			s.created_at, s.updated_at
		FROM rule_community_account_sources s
		LEFT JOIN rule_provider_adapters p ON p.id = s.provider_adapter_id
		ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleCommunityAccountSource
	for rows.Next() {
		item, err := scanRuleCommunityAccountSource(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRuleCommunityAccountSource(ctx context.Context, id int64) (model.RuleCommunityAccountSource, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.name, s.provider_type, s.provider_adapter_id, COALESCE(p.name, ''), COALESCE(p.health_status, ''),
			CASE WHEN COALESCE(p.retry_exhausted, false) THEN 'exhausted' WHEN COALESCE(p.attempt_count, 0) > 0 THEN 'retrying' ELSE 'ready' END,
			s.endpoint, s.enabled, s.timeout_sec,
			s.credential_alias, s.credential_fingerprint, s.credential_last_four, s.credential_expires_at, s.credential_last_validated_at, s.credential_status,
			s.subscription_status, s.entitlement_summary, s.package_count, s.status, s.last_sync_at, s.last_error,
			(SELECT count(*) FROM rule_review_queue q WHERE q.source_identity = 'account:' || s.id AND q.state = 'queued') AS recommendation_count,
			s.created_at, s.updated_at
		FROM rule_community_account_sources s
		LEFT JOIN rule_provider_adapters p ON p.id = s.provider_adapter_id
		WHERE s.id = $1`, id)
	item, err := scanRuleCommunityAccountSource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleCommunityAccountSource{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateRuleCommunityAccountSource(ctx context.Context, item model.RuleCommunityAccountSource, secret model.RuleCommunityAccountSecret) (model.RuleCommunityAccountSource, error) {
	item.Credential = postgresRedactCredential(item.Credential, secret.Secret, time.Now().UTC())
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rule_community_account_sources (
			name, provider_type, provider_adapter_id, endpoint, enabled, timeout_sec,
			credential_alias, credential_fingerprint, credential_last_four, credential_expires_at, credential_last_validated_at, credential_status, credential_secret,
			subscription_status, entitlement_summary, package_count, status, last_error
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		RETURNING id, created_at, updated_at`,
		item.Name, item.ProviderType, item.ProviderAdapterID, item.Endpoint, item.Enabled, item.TimeoutSec,
		item.Credential.Alias, item.Credential.Fingerprint, item.Credential.LastFour, nullableTime(item.Credential.ExpiresAt), nullableTime(item.Credential.LastValidatedAt), item.Credential.Status, secret.Secret,
		item.SubscriptionStatus, item.EntitlementSummary, item.PackageCount, item.Status, item.LastError).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateRuleCommunityAccountSource(ctx context.Context, id int64, item model.RuleCommunityAccountSource, secret model.RuleCommunityAccountSecret) (model.RuleCommunityAccountSource, error) {
	existing, err := s.GetRuleCommunityAccountSource(ctx, id)
	if err != nil {
		return model.RuleCommunityAccountSource{}, err
	}
	if secret.Secret == "" {
		item.Credential = existing.Credential
	} else {
		item.Credential = postgresRedactCredential(item.Credential, secret.Secret, time.Now().UTC())
	}
	err = s.db.QueryRowContext(ctx, `
		UPDATE rule_community_account_sources
		SET name = $2, provider_type = $3, provider_adapter_id = $4, endpoint = $5, enabled = $6, timeout_sec = $7,
			credential_alias = $8, credential_fingerprint = $9, credential_last_four = $10,
			credential_expires_at = $11, credential_last_validated_at = $12, credential_status = $13,
			credential_secret = CASE WHEN $14 = '' THEN credential_secret ELSE $14 END,
			subscription_status = $15, entitlement_summary = $16, package_count = $17,
			status = $18, last_error = $19, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`,
		id, item.Name, item.ProviderType, item.ProviderAdapterID, item.Endpoint, item.Enabled, item.TimeoutSec,
		item.Credential.Alias, item.Credential.Fingerprint, item.Credential.LastFour,
		nullableTime(item.Credential.ExpiresAt), nullableTime(item.Credential.LastValidatedAt), item.Credential.Status, secret.Secret,
		item.SubscriptionStatus, item.EntitlementSummary, item.PackageCount, item.Status, item.LastError).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleCommunityAccountSource{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) DeleteRuleCommunityAccountSource(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM rule_community_account_sources WHERE id = $1`, id)
	return checkRowsAffected(result, err)
}

func (s *PostgresStore) RefreshRuleCommunityAccountSource(ctx context.Context, id int64, item model.RuleCommunityAccountSource, queue []model.RuleReviewQueueItem) (model.RuleCommunityAccountSource, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.RuleCommunityAccountSource{}, err
	}
	defer tx.Rollback()
	var credentialExpires sql.NullTime
	var credentialValidated sql.NullTime
	var lastSync sql.NullTime
	err = tx.QueryRowContext(ctx, `
		UPDATE rule_community_account_sources
		SET subscription_status = $2, entitlement_summary = $3, package_count = $4, status = $5,
			last_sync_at = $6, last_error = $7, updated_at = now()
		WHERE id = $1
		RETURNING id, name, provider_type, provider_adapter_id, '', '', '', endpoint, enabled, timeout_sec,
			credential_alias, credential_fingerprint, credential_last_four, credential_expires_at, credential_last_validated_at, credential_status,
			subscription_status, entitlement_summary, package_count, status, last_sync_at, last_error, 0, created_at, updated_at`,
		id, item.SubscriptionStatus, item.EntitlementSummary, item.PackageCount, item.Status, nullableTime(item.LastSyncAt), item.LastError).
		Scan(&item.ID, &item.Name, &item.ProviderType, &item.ProviderAdapterID, &item.ProviderAdapterName, &item.ProviderHealth, &item.ProviderRetryState, &item.Endpoint, &item.Enabled, &item.TimeoutSec,
			&item.Credential.Alias, &item.Credential.Fingerprint, &item.Credential.LastFour, &credentialExpires, &credentialValidated, &item.Credential.Status,
			&item.SubscriptionStatus, &item.EntitlementSummary, &item.PackageCount, &item.Status, &lastSync, &item.LastError, &item.RecommendationCount, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleCommunityAccountSource{}, ErrNotFound
	}
	if err != nil {
		return model.RuleCommunityAccountSource{}, err
	}
	if credentialExpires.Valid {
		item.Credential.ExpiresAt = credentialExpires.Time
	}
	if credentialValidated.Valid {
		item.Credential.LastValidatedAt = credentialValidated.Time
	}
	if lastSync.Valid {
		item.LastSyncAt = lastSync.Time
	}
	for _, q := range queue {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO rule_review_queue (item_type, package_id, package_version, current_version, source_identity, recommendation, risk_summary, signature_status, compatibility_status, state, actor)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			q.ItemType, q.PackageID, q.PackageVersion, q.CurrentVersion, q.SourceIdentity, q.Recommendation, q.RiskSummary, q.SignatureStatus, q.CompatibilityStatus, q.State, q.Actor); err != nil {
			return model.RuleCommunityAccountSource{}, err
		}
	}
	return item, tx.Commit()
}

func (s *PostgresStore) ListRuleContributionTargets(ctx context.Context) ([]model.RuleContributionTarget, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, provider, endpoint, channel, enabled,
			credential_alias, credential_fingerprint, credential_last_four, credential_expires_at, credential_last_validated_at, credential_status,
			status, last_push_at, last_error, created_at, updated_at
		FROM rule_contribution_targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleContributionTarget
	for rows.Next() {
		item, err := scanRuleContributionTarget(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRuleContributionTarget(ctx context.Context, id int64) (model.RuleContributionTarget, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, provider, endpoint, channel, enabled,
			credential_alias, credential_fingerprint, credential_last_four, credential_expires_at, credential_last_validated_at, credential_status,
			status, last_push_at, last_error, created_at, updated_at
		FROM rule_contribution_targets WHERE id = $1`, id)
	item, err := scanRuleContributionTarget(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleContributionTarget{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateRuleContributionTarget(ctx context.Context, item model.RuleContributionTarget, secret model.RuleCommunityAccountSecret) (model.RuleContributionTarget, error) {
	item.Credential = postgresRedactCredential(item.Credential, secret.Secret, time.Now().UTC())
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rule_contribution_targets (
			name, provider, endpoint, channel, enabled, credential_alias, credential_fingerprint, credential_last_four,
			credential_expires_at, credential_last_validated_at, credential_status, credential_secret, status, last_error
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, created_at, updated_at`,
		item.Name, item.Provider, item.Endpoint, item.Channel, item.Enabled, item.Credential.Alias, item.Credential.Fingerprint, item.Credential.LastFour,
		nullableTime(item.Credential.ExpiresAt), nullableTime(item.Credential.LastValidatedAt), item.Credential.Status, secret.Secret, item.Status, item.LastError).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) CreateRuleContributionPushAttempt(ctx context.Context, item model.RuleContributionPushAttempt) (model.RuleContributionPushAttempt, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rule_contribution_push_attempts (target_id, target_name, package_id, package_version, checksum, status, remote_reference, error, actor, preview_only)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at`,
		item.TargetID, item.TargetName, item.PackageID, item.PackageVersion, item.Checksum, item.Status, item.RemoteReference, item.Error, item.Actor, item.PreviewOnly).
		Scan(&item.ID, &item.CreatedAt)
	if err != nil {
		return item, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE rule_contribution_targets SET status = $2, last_push_at = $3, last_error = $4, updated_at = now() WHERE id = $1`, item.TargetID, item.Status, item.CreatedAt, item.Error)
	return item, nil
}

func (s *PostgresStore) ListRuleContributionPushAttempts(ctx context.Context) ([]model.RuleContributionPushAttempt, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_id, target_name, package_id, package_version, checksum, status, remote_reference, error, actor, preview_only, created_at
		FROM rule_contribution_push_attempts ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleContributionPushAttempt
	for rows.Next() {
		var item model.RuleContributionPushAttempt
		if err := rows.Scan(&item.ID, &item.TargetID, &item.TargetName, &item.PackageID, &item.PackageVersion, &item.Checksum, &item.Status, &item.RemoteReference, &item.Error, &item.Actor, &item.PreviewOnly, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) ListRuleReviewQueueItems(ctx context.Context) ([]model.RuleReviewQueueItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, item_type, package_id, package_version, current_version, source_identity, recommendation, risk_summary,
			signature_status, compatibility_status, state, decision_reason, actor, created_at, updated_at
		FROM rule_review_queue ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleReviewQueueItem
	for rows.Next() {
		item, err := scanRuleReviewQueueItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRuleReviewQueueItem(ctx context.Context, id int64) (model.RuleReviewQueueItem, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, item_type, package_id, package_version, current_version, source_identity, recommendation, risk_summary,
			signature_status, compatibility_status, state, decision_reason, actor, created_at, updated_at
		FROM rule_review_queue WHERE id = $1`, id)
	item, err := scanRuleReviewQueueItem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleReviewQueueItem{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateRuleReviewQueueItem(ctx context.Context, item model.RuleReviewQueueItem) (model.RuleReviewQueueItem, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rule_review_queue (item_type, package_id, package_version, current_version, source_identity, recommendation, risk_summary, signature_status, compatibility_status, state, actor)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at`,
		item.ItemType, item.PackageID, item.PackageVersion, item.CurrentVersion, item.SourceIdentity, item.Recommendation, item.RiskSummary, item.SignatureStatus, item.CompatibilityStatus, item.State, item.Actor).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateRuleReviewQueueItem(ctx context.Context, id int64, item model.RuleReviewQueueItem) (model.RuleReviewQueueItem, error) {
	err := s.db.QueryRowContext(ctx, `
		UPDATE rule_review_queue
		SET state = $2, decision_reason = $3, actor = $4, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`, id, item.State, item.DecisionReason, item.Actor).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleReviewQueueItem{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) ListRuleFeedback(ctx context.Context) ([]model.RuleFeedback, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, rule_id, package_id, package_rule_id, attack_log_id, reason, severity, status, redacted_sample, actor, created_at, updated_at FROM rule_feedback ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleFeedback
	for rows.Next() {
		item, err := scanRuleFeedback(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) CreateRuleFeedback(ctx context.Context, item model.RuleFeedback) (model.RuleFeedback, error) {
	sample, _ := json.Marshal(item.RedactedSample)
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rule_feedback (rule_id, package_id, package_rule_id, attack_log_id, reason, severity, status, redacted_sample, actor)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`,
		item.RuleID, item.PackageID, item.PackageRuleID, item.AttackLogID, item.Reason, item.Severity, item.Status, string(sample), item.Actor).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) ListRuleFeedbackSuggestions(ctx context.Context) ([]model.RuleFeedbackSuggestion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, feedback_id, rule_id, proposed_change, risk_warning, confidence, state, test_result, actor, created_at, updated_at FROM rule_feedback_suggestions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.RuleFeedbackSuggestion
	for rows.Next() {
		item, err := scanRuleFeedbackSuggestion(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetRuleFeedbackSuggestion(ctx context.Context, id int64) (model.RuleFeedbackSuggestion, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, feedback_id, rule_id, proposed_change, risk_warning, confidence, state, test_result, actor, created_at, updated_at FROM rule_feedback_suggestions WHERE id = $1`, id)
	item, err := scanRuleFeedbackSuggestion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleFeedbackSuggestion{}, ErrNotFound
	}
	return item, err
}

func (s *PostgresStore) CreateRuleFeedbackSuggestion(ctx context.Context, item model.RuleFeedbackSuggestion) (model.RuleFeedbackSuggestion, error) {
	result, _ := json.Marshal(item.TestResult)
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO rule_feedback_suggestions (feedback_id, rule_id, proposed_change, risk_warning, confidence, state, test_result, actor)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at`,
		item.FeedbackID, item.RuleID, item.ProposedChange, item.RiskWarning, item.Confidence, item.State, string(result), item.Actor).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *PostgresStore) UpdateRuleFeedbackSuggestion(ctx context.Context, id int64, item model.RuleFeedbackSuggestion) (model.RuleFeedbackSuggestion, error) {
	result, _ := json.Marshal(item.TestResult)
	err := s.db.QueryRowContext(ctx, `
		UPDATE rule_feedback_suggestions
		SET state = $2, test_result = $3, actor = $4, updated_at = now()
		WHERE id = $1
		RETURNING id, created_at, updated_at`, id, item.State, string(result), item.Actor).
		Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.RuleFeedbackSuggestion{}, ErrNotFound
	}
	return item, err
}

type catalogPackageScanner interface {
	Scan(dest ...any) error
}

type ruleCommunityAccountScanner interface {
	Scan(dest ...any) error
}

type ruleProviderAdapterScanner interface {
	Scan(dest ...any) error
}

func scanRuleProviderAdapter(row ruleProviderAdapterScanner) (model.RuleProviderAdapter, error) {
	var item model.RuleProviderAdapter
	var credentialExpires sql.NullTime
	var credentialValidated sql.NullTime
	var lastSync sql.NullTime
	var lastFailed sql.NullTime
	var nextRetry sql.NullTime
	err := row.Scan(
		&item.ID, &item.Name, &item.ProviderType, &item.Endpoint, &item.AuthMode, &item.Enabled, &item.TimeoutSec,
		&item.RetryPolicy.MaxAttempts, &item.RetryPolicy.BackoffSec,
		&item.Credential.Alias, &item.Credential.Fingerprint, &item.Credential.LastFour, &credentialExpires, &credentialValidated, &item.Credential.Status,
		&item.HealthStatus, &item.SyncStatus, &lastSync, &lastFailed, &item.LastError, &item.AttemptCount, &nextRetry, &item.RetryExhausted,
		&item.PackageCount, &item.CreatedAt, &item.UpdatedAt,
	)
	if credentialExpires.Valid {
		item.Credential.ExpiresAt = credentialExpires.Time
	}
	if credentialValidated.Valid {
		item.Credential.LastValidatedAt = credentialValidated.Time
	}
	if lastSync.Valid {
		item.LastSyncAt = lastSync.Time
	}
	if lastFailed.Valid {
		item.LastFailedSyncAt = lastFailed.Time
	}
	if nextRetry.Valid {
		item.NextRetryAt = nextRetry.Time
	}
	return item, err
}

type ruleProviderPackageScanner interface {
	Scan(dest ...any) error
}

func scanRuleProviderPackage(row ruleProviderPackageScanner) (model.RuleProviderPackage, error) {
	var item model.RuleProviderPackage
	var lastSynced sql.NullTime
	err := row.Scan(
		&item.ID, &item.ProviderID, &item.ProviderName, &item.ProviderType, &item.ProviderPackageRef, &item.PackageID, &item.Name, &item.Version, &item.Compatibility, &item.Checksum,
		&item.Signature.KeyID, &item.Signature.Checksum, &item.Signature.Signature, &item.Signature.ExpiresAt, &item.SignatureStatus,
		&item.UpdatedAtText, &item.ManifestURL, &item.PackageJSON, &item.SourceIdentity, &item.EntitlementState, &item.SyncStatus, &item.Stale, &lastSynced, &item.CreatedAt, &item.UpdatedAt,
	)
	if lastSynced.Valid {
		item.LastSyncedAt = lastSynced.Time
	}
	return item, err
}

func scanRuleCommunityAccountSource(row ruleCommunityAccountScanner) (model.RuleCommunityAccountSource, error) {
	var item model.RuleCommunityAccountSource
	var credentialExpires sql.NullTime
	var credentialValidated sql.NullTime
	var lastSync sql.NullTime
	err := row.Scan(
		&item.ID, &item.Name, &item.ProviderType, &item.ProviderAdapterID, &item.ProviderAdapterName, &item.ProviderHealth, &item.ProviderRetryState, &item.Endpoint, &item.Enabled, &item.TimeoutSec,
		&item.Credential.Alias, &item.Credential.Fingerprint, &item.Credential.LastFour, &credentialExpires, &credentialValidated, &item.Credential.Status,
		&item.SubscriptionStatus, &item.EntitlementSummary, &item.PackageCount, &item.Status, &lastSync, &item.LastError,
		&item.RecommendationCount, &item.CreatedAt, &item.UpdatedAt,
	)
	if credentialExpires.Valid {
		item.Credential.ExpiresAt = credentialExpires.Time
	}
	if credentialValidated.Valid {
		item.Credential.LastValidatedAt = credentialValidated.Time
	}
	if lastSync.Valid {
		item.LastSyncAt = lastSync.Time
	}
	return item, err
}

type ruleContributionTargetScanner interface {
	Scan(dest ...any) error
}

func scanRuleContributionTarget(row ruleContributionTargetScanner) (model.RuleContributionTarget, error) {
	var item model.RuleContributionTarget
	var credentialExpires sql.NullTime
	var credentialValidated sql.NullTime
	var lastPush sql.NullTime
	err := row.Scan(
		&item.ID, &item.Name, &item.Provider, &item.Endpoint, &item.Channel, &item.Enabled,
		&item.Credential.Alias, &item.Credential.Fingerprint, &item.Credential.LastFour, &credentialExpires, &credentialValidated, &item.Credential.Status,
		&item.Status, &lastPush, &item.LastError, &item.CreatedAt, &item.UpdatedAt,
	)
	if credentialExpires.Valid {
		item.Credential.ExpiresAt = credentialExpires.Time
	}
	if credentialValidated.Valid {
		item.Credential.LastValidatedAt = credentialValidated.Time
	}
	if lastPush.Valid {
		item.LastPushAt = lastPush.Time
	}
	return item, err
}

type ruleReviewQueueScanner interface {
	Scan(dest ...any) error
}

func scanRuleReviewQueueItem(row ruleReviewQueueScanner) (model.RuleReviewQueueItem, error) {
	var item model.RuleReviewQueueItem
	err := row.Scan(
		&item.ID, &item.ItemType, &item.PackageID, &item.PackageVersion, &item.CurrentVersion, &item.SourceIdentity, &item.Recommendation,
		&item.RiskSummary, &item.SignatureStatus, &item.CompatibilityStatus, &item.State, &item.DecisionReason, &item.Actor, &item.CreatedAt, &item.UpdatedAt,
	)
	return item, err
}

type ruleFeedbackScanner interface {
	Scan(dest ...any) error
}

func scanRuleFeedback(row ruleFeedbackScanner) (model.RuleFeedback, error) {
	var item model.RuleFeedback
	var sample string
	err := row.Scan(&item.ID, &item.RuleID, &item.PackageID, &item.PackageRuleID, &item.AttackLogID, &item.Reason, &item.Severity, &item.Status, &sample, &item.Actor, &item.CreatedAt, &item.UpdatedAt)
	if sample != "" {
		_ = json.Unmarshal([]byte(sample), &item.RedactedSample)
	}
	return item, err
}

type ruleFeedbackSuggestionScanner interface {
	Scan(dest ...any) error
}

func scanRuleFeedbackSuggestion(row ruleFeedbackSuggestionScanner) (model.RuleFeedbackSuggestion, error) {
	var item model.RuleFeedbackSuggestion
	var result string
	err := row.Scan(&item.ID, &item.FeedbackID, &item.RuleID, &item.ProposedChange, &item.RiskWarning, &item.Confidence, &item.State, &result, &item.Actor, &item.CreatedAt, &item.UpdatedAt)
	if result != "" {
		_ = json.Unmarshal([]byte(result), &item.TestResult)
	}
	return item, err
}

func postgresRedactCredential(meta model.RuleAccountCredential, secret string, now time.Time) model.RuleAccountCredential {
	if meta.Alias == "" {
		meta.Alias = "default"
	}
	if secret != "" {
		meta.LastFour = lastFour(secret)
		meta.Fingerprint = "sha256:" + stringLengthFingerprint(secret) + ":" + lastFour(secret)
		meta.LastValidatedAt = now
		meta.Status = "configured"
	}
	if meta.Status == "" {
		meta.Status = "not-configured"
	}
	return meta
}

func stringLengthFingerprint(value string) string {
	return strings.TrimSpace(time.Unix(int64(len(value)), 0).UTC().Format("150405"))
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

type certificateScanner interface {
	Scan(dest ...any) error
}

func scanCertificate(row certificateScanner) (model.Certificate, error) {
	var item model.Certificate
	var domains string
	err := row.Scan(&item.ID, &item.Name, &domains, &item.CertPEM, &item.KeyPEM, &item.NotBefore, &item.NotAfter, &item.Fingerprint, &item.CreatedAt, &item.UpdatedAt)
	item.Domains = splitCSV(domains)
	return item, err
}

func encodeApplicationProxyConfig(config *model.ApplicationProxyConfig) (string, error) {
	if config == nil {
		return "", nil
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func decodeApplicationProxyConfig(value string) (*model.ApplicationProxyConfig, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var config model.ApplicationProxyConfig
	if err := json.Unmarshal([]byte(value), &config); err != nil {
		return nil, err
	}
	model.NormalizeApplicationProxyConfig(&config)
	if err := model.ValidateApplicationProxyConfig(config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (s *PostgresStore) certificateExists(ctx context.Context, id int64) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM certificates WHERE id = $1)`, id).Scan(&exists)
	return exists, err
}

func (s *PostgresStore) loadApplicationChildren(ctx context.Context, item *model.Application) error {
	hostRows, err := s.db.QueryContext(ctx, `
		SELECT id, application_id, host, is_primary
		FROM application_hosts
		WHERE application_id = $1
		ORDER BY id`, item.ID)
	if err != nil {
		return err
	}
	defer hostRows.Close()
	for hostRows.Next() {
		var host model.ApplicationHost
		if err := hostRows.Scan(&host.ID, &host.ApplicationID, &host.Host, &host.IsPrimary); err != nil {
			return err
		}
		item.Hosts = append(item.Hosts, host)
	}
	if err := hostRows.Err(); err != nil {
		return err
	}

	listenerRows, err := s.db.QueryContext(ctx, `
		SELECT id, application_id, port, protocol, certificate_id, enabled
		FROM application_listeners
		WHERE application_id = $1
		ORDER BY id`, item.ID)
	if err != nil {
		return err
	}
	defer listenerRows.Close()
	for listenerRows.Next() {
		var listener model.ApplicationListener
		if err := listenerRows.Scan(&listener.ID, &listener.ApplicationID, &listener.Port, &listener.Protocol, &listener.CertificateID, &listener.Enabled); err != nil {
			return err
		}
		item.Listeners = append(item.Listeners, listener)
	}
	if err := listenerRows.Err(); err != nil {
		return err
	}

	upstreamRows, err := s.db.QueryContext(ctx, `
		SELECT id, application_id, name, url, weight, enabled
		FROM application_upstreams
		WHERE application_id = $1
		ORDER BY id`, item.ID)
	if err != nil {
		return err
	}
	defer upstreamRows.Close()
	for upstreamRows.Next() {
		var upstream model.ApplicationUpstream
		if err := upstreamRows.Scan(&upstream.ID, &upstream.ApplicationID, &upstream.Name, &upstream.URL, &upstream.Weight, &upstream.Enabled); err != nil {
			return err
		}
		item.Upstreams = append(item.Upstreams, upstream)
	}
	if err := upstreamRows.Err(); err != nil {
		return err
	}

	routeRows, err := s.db.QueryContext(ctx, `
		SELECT id, application_id, name, path, path_match, upstream_name, priority, enabled, proxy_config_json
		FROM application_routes
		WHERE application_id = $1
		ORDER BY priority, id`, item.ID)
	if err != nil {
		return err
	}
	defer routeRows.Close()
	for routeRows.Next() {
		var route model.ApplicationRoute
		var proxyConfigJSON string
		if err := routeRows.Scan(&route.ID, &route.ApplicationID, &route.Name, &route.Path, &route.PathMatch, &route.UpstreamName, &route.Priority, &route.Enabled, &proxyConfigJSON); err != nil {
			return err
		}
		var err error
		if route.ProxyConfig, err = decodeApplicationProxyConfig(proxyConfigJSON); err != nil {
			return err
		}
		item.Routes = append(item.Routes, route)
	}
	return routeRows.Err()
}

func replaceApplicationChildren(ctx context.Context, tx *sql.Tx, item *model.Application) error {
	for _, host := range item.Hosts {
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO application_hosts (application_id, host, is_primary)
			VALUES ($1, $2, $3)
			RETURNING id`, item.ID, host.Host, host.IsPrimary).Scan(&host.ID); err != nil {
			return err
		}
	}
	for _, listener := range item.Listeners {
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO application_listeners (application_id, port, protocol, certificate_id, enabled)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id`, item.ID, listener.Port, listener.Protocol, listener.CertificateID, listener.Enabled).Scan(&listener.ID); err != nil {
			return err
		}
	}
	for _, upstream := range item.Upstreams {
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO application_upstreams (application_id, name, url, weight, enabled)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id`, item.ID, upstream.Name, upstream.URL, upstream.Weight, upstream.Enabled).Scan(&upstream.ID); err != nil {
			return err
		}
	}
	for _, route := range item.Routes {
		proxyConfigJSON, err := encodeApplicationProxyConfig(route.ProxyConfig)
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO application_routes (application_id, name, path, path_match, upstream_name, priority, enabled, proxy_config_json)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			RETURNING id`, item.ID, route.Name, route.Path, route.PathMatch, route.UpstreamName, route.Priority, route.Enabled, proxyConfigJSON).Scan(&route.ID); err != nil {
			return err
		}
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

func validateApplicationRefs(ctx context.Context, tx *sql.Tx, ids []int64) error {
	for _, id := range ids {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE id = $1)`, id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM sites WHERE id = $1)`, id).Scan(&exists); err != nil {
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

type protectionRuleScanner interface {
	Scan(dest ...any) error
}

type encodedProtectionRule struct {
	Match     []byte
	Limit     []byte
	Upload    []byte
	Challenge []byte
	Dynamic   []byte
	Action    []byte
}

func encodeProtectionRule(item model.ProtectionRule) (encodedProtectionRule, error) {
	var out encodedProtectionRule
	var err error
	if out.Match, err = json.Marshal(item.Match); err != nil {
		return out, err
	}
	if out.Limit, err = json.Marshal(item.Limit); err != nil {
		return out, err
	}
	if out.Upload, err = marshalNullable(item.Upload); err != nil {
		return out, err
	}
	if out.Challenge, err = marshalNullable(item.Challenge); err != nil {
		return out, err
	}
	if out.Dynamic, err = marshalNullable(item.Dynamic); err != nil {
		return out, err
	}
	if out.Action, err = json.Marshal(item.Action); err != nil {
		return out, err
	}
	return out, nil
}

func marshalNullable(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	return json.Marshal(value)
}

func scanProtectionRule(scanner protectionRuleScanner) (model.ProtectionRule, error) {
	var item model.ProtectionRule
	var matchJSON, limitJSON, actionJSON []byte
	var uploadJSON, challengeJSON, dynamicJSON []byte
	err := scanner.Scan(
		&item.ID, &item.Name, &item.Module, &item.Category, &item.SiteID, &item.Enabled, &item.Priority,
		&matchJSON, &limitJSON, &uploadJSON, &challengeJSON, &dynamicJSON, &actionJSON,
		&item.Source, &item.MigrationStatus, &item.LegacyRef, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return model.ProtectionRule{}, err
	}
	if len(matchJSON) > 0 {
		if err := json.Unmarshal(matchJSON, &item.Match); err != nil {
			return model.ProtectionRule{}, err
		}
	}
	if len(limitJSON) > 0 {
		if err := json.Unmarshal(limitJSON, &item.Limit); err != nil {
			return model.ProtectionRule{}, err
		}
	}
	if len(uploadJSON) > 0 {
		var upload model.ProtectionRuleUpload
		if err := json.Unmarshal(uploadJSON, &upload); err != nil {
			return model.ProtectionRule{}, err
		}
		item.Upload = &upload
	}
	if len(challengeJSON) > 0 {
		var challenge model.ProtectionRuleChallenge
		if err := json.Unmarshal(challengeJSON, &challenge); err != nil {
			return model.ProtectionRule{}, err
		}
		item.Challenge = &challenge
	}
	if len(dynamicJSON) > 0 {
		var dynamic model.ProtectionRuleDynamic
		if err := json.Unmarshal(dynamicJSON, &dynamic); err != nil {
			return model.ProtectionRule{}, err
		}
		item.Dynamic = &dynamic
	}
	if len(actionJSON) > 0 {
		if err := json.Unmarshal(actionJSON, &item.Action); err != nil {
			return model.ProtectionRule{}, err
		}
	}
	return protectionrules.Normalize(item), nil
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
