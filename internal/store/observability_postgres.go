package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"litewaf-api/internal/model"
)

func (s *PostgresStore) CreateAccessLog(ctx context.Context, item model.AccessLog) (model.AccessLog, error) {
	createdAt := nullableTime(item.CreatedAt)
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO access_logs (request_id, site_id, host, method, uri, status, upstream_status, duration_ms, client_ip, user_agent, disposition, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, COALESCE($12::timestamptz, now()))
		RETURNING id, created_at`,
		item.RequestID, item.SiteID, item.Host, item.Method, item.URI, item.Status, item.UpstreamStatus, item.DurationMS, item.ClientIP, item.UserAgent, item.Disposition, createdAt).
		Scan(&item.ID, &item.CreatedAt)
	item.Time = item.CreatedAt.Format(time.RFC3339)
	return item, err
}

func (s *PostgresStore) ListAccessLogs(ctx context.Context, filter model.AccessLogFilter) ([]model.AccessLog, error) {
	limit := normalizeLimit(filter.Pagination.Limit)
	offset := filter.Pagination.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, request_id, site_id, host, method, uri, status, upstream_status, duration_ms, client_ip, user_agent, disposition, created_at
		FROM access_logs
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2 = '' OR host = $2)
			AND ($3 = '' OR client_ip = $3)
			AND ($4 = '' OR method = $4)
			AND ($5 = '' OR uri ILIKE '%' || $5 || '%')
			AND ($6::integer = 0 OR status = $6)
			AND ($7 = '' OR disposition = $7)
			AND ($8::timestamptz IS NULL OR created_at >= $8)
			AND ($9::timestamptz IS NULL OR created_at <= $9)
		ORDER BY id DESC
		LIMIT $10 OFFSET $11`,
		filter.SiteID, filter.Host, filter.ClientIP, filter.Method, filter.URI, filter.Status, filter.Disposition,
		nullableTime(filter.Since), nullableTime(filter.Until), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.AccessLog
	for rows.Next() {
		var item model.AccessLog
		if err := rows.Scan(&item.ID, &item.RequestID, &item.SiteID, &item.Host, &item.Method, &item.URI, &item.Status, &item.UpstreamStatus, &item.DurationMS, &item.ClientIP, &item.UserAgent, &item.Disposition, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) CreateWAFEvent(ctx context.Context, item model.WAFEvent) (model.WAFEvent, error) {
	createdAt := nullableTime(item.CreatedAt)
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO waf_events (
			request_id, site_id, event_type, rule_id, rule_type, target, action, disposition,
			client_ip, method, uri, summary, access_list_id, rate_limit_id,
			module, category, rule_name, attack_type, group_name, counter, window_sec,
			advanced_target, normalized_value, score, threshold, matched_rule_ids,
			body_metadata, upload_metadata, ban_reason, ban_duration_sec, ban_remaining_sec,
			challenge_mode, challenge_result, bot_result, bot_reason, device_signal,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, COALESCE($37::timestamptz, now()))
		RETURNING id, created_at`,
		item.RequestID, item.SiteID, item.EventType, item.RuleID, item.RuleType, item.Target, item.Action, item.Disposition,
		item.ClientIP, item.Method, item.URI, item.Summary, item.AccessListID, item.RateLimitID,
		item.Module, item.Category, item.RuleName, item.AttackType, item.GroupName, item.Counter, item.WindowSec,
		item.AdvancedTarget, item.NormalizedValue, item.Score, item.Threshold, item.MatchedRuleIDs,
		item.BodyMetadata, item.UploadMetadata, item.BanReason, item.BanDurationSec, item.BanRemainingSec,
		item.ChallengeMode, item.ChallengeResult, item.BotResult, item.BotReason, item.DeviceSignal,
		createdAt).
		Scan(&item.ID, &item.CreatedAt)
	item.Time = item.CreatedAt.Format(time.RFC3339)
	if err != nil {
		return item, err
	}
	if err := s.projectDynamicBanEvent(ctx, item); err != nil {
		return item, err
	}
	return item, nil
}

func (s *PostgresStore) ListWAFEvents(ctx context.Context, filter model.WAFEventFilter) ([]model.WAFEvent, error) {
	limit := normalizeLimit(filter.Pagination.Limit)
	offset := filter.Pagination.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, request_id, site_id, event_type, rule_id, rule_type, target, action, disposition,
			client_ip, method, uri, summary, access_list_id, rate_limit_id,
			module, category, rule_name, attack_type, group_name, counter, window_sec,
			advanced_target, normalized_value, score, threshold, matched_rule_ids,
			body_metadata, upload_metadata, ban_reason, ban_duration_sec, ban_remaining_sec,
			challenge_mode, challenge_result, bot_result, bot_reason, device_signal,
			created_at
		FROM waf_events
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2 = '' OR client_ip = $2)
			AND ($3::bigint = 0 OR rule_id = $3)
			AND ($4 = '' OR action = $4)
			AND ($5 = '' OR disposition = $5)
			AND ($6 = '' OR event_type = $6)
			AND ($7 = '' OR module = $7)
			AND ($8 = '' OR attack_type = $8)
			AND ($9 = '' OR advanced_target = $9 OR target = $9)
			AND ($10 = '' OR challenge_result = $10)
			AND ($11::integer = 0 OR score >= $11)
			AND ($12 = '' OR advanced_target = $12)
			AND ($13 = '' OR bot_result = $13)
			AND ($14::timestamptz IS NULL OR created_at >= $14)
			AND ($15::timestamptz IS NULL OR created_at <= $15)
		ORDER BY id DESC
		LIMIT $16 OFFSET $17`,
		filter.SiteID, filter.ClientIP, filter.RuleID, filter.Action, filter.Disposition, filter.EventType,
		filter.Module, filter.AttackType, filter.AdvancedTarget, filter.ChallengeResult, filter.MinScore, filter.DynamicResult, filter.BotResult, nullableTime(filter.Since), nullableTime(filter.Until), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.WAFEvent
	for rows.Next() {
		var item model.WAFEvent
		if err := rows.Scan(
			&item.ID, &item.RequestID, &item.SiteID, &item.EventType, &item.RuleID, &item.RuleType, &item.Target, &item.Action, &item.Disposition,
			&item.ClientIP, &item.Method, &item.URI, &item.Summary, &item.AccessListID, &item.RateLimitID,
			&item.Module, &item.Category, &item.RuleName, &item.AttackType, &item.GroupName, &item.Counter, &item.WindowSec,
			&item.AdvancedTarget, &item.NormalizedValue, &item.Score, &item.Threshold, &item.MatchedRuleIDs,
			&item.BodyMetadata, &item.UploadMetadata, &item.BanReason, &item.BanDurationSec, &item.BanRemainingSec,
			&item.ChallengeMode, &item.ChallengeResult, &item.BotResult, &item.BotReason, &item.DeviceSignal,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetObservabilitySummary(ctx context.Context, filter model.ObservabilitySummaryFilter) (model.ObservabilitySummary, error) {
	summary := emptyObservabilitySummary()
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*),
			count(*) FILTER (WHERE disposition IN ('blocked', 'rejected')),
			count(*) FILTER (WHERE disposition = 'rate-limited')
		FROM access_logs
		WHERE ($1::timestamptz IS NULL OR created_at >= $1)
			AND ($2::timestamptz IS NULL OR created_at <= $2)`,
		nullableTime(filter.Since), nullableTime(filter.Until)).
		Scan(&summary.Requests, &summary.BlockedRequests, &summary.RateLimited); err != nil {
		return summary, err
	}
	var eventBlocked int64
	var eventRateLimited int64
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(*),
			count(*) FILTER (WHERE disposition IN ('blocked', 'rejected')),
			count(*) FILTER (WHERE event_type = 'rate-limit' OR rate_limit_id > 0),
			count(*) FILTER (WHERE event_type = 'score-threshold'),
			count(*) FILTER (WHERE event_type = 'body-inspection' OR advanced_target IN ('body', 'body_json', 'body_form')),
			count(*) FILTER (WHERE event_type = 'upload-inspection' OR advanced_target IN ('upload', 'upload_filename', 'upload_extension', 'upload_mime', 'upload_size')),
			count(*) FILTER (WHERE event_type = 'dynamic-ban')
		FROM waf_events
		WHERE ($1::timestamptz IS NULL OR created_at >= $1)
			AND ($2::timestamptz IS NULL OR created_at <= $2)`,
		nullableTime(filter.Since), nullableTime(filter.Until)).
		Scan(&summary.WAFMatches, &eventBlocked, &eventRateLimited, &summary.ScoreBlocks, &summary.BodyDetections, &summary.UploadDetections, &summary.DynamicBans); err != nil {
		return summary, err
	}
	summary.BlockedRequests += eventBlocked
	summary.RateLimited += eventRateLimited

	limit := normalizeSummaryLimit(filter.Limit)
	var err error
	summary.TopIPs, err = s.summaryCounts(ctx, "access_logs", "client_ip", filter, limit)
	if err != nil {
		return summary, err
	}
	summary.TopURIs, err = s.summaryCounts(ctx, "access_logs", "uri", filter, limit)
	if err != nil {
		return summary, err
	}
	summary.TopRules, err = s.summaryCounts(ctx, "waf_events", "rule_id::text", filter, limit)
	if err != nil {
		return summary, err
	}
	summary.AttackTypes, err = s.summaryCounts(ctx, "waf_events", "event_type", filter, limit)
	if err != nil {
		return summary, err
	}
	summary.AccessControl, err = s.accessControlSummaryCounts(ctx, filter, limit)
	if err != nil {
		return summary, err
	}
	summary.AttackProtection, err = s.attackProtectionSummaryCounts(ctx, filter, limit)
	if err != nil {
		return summary, err
	}
	summary.UploadProtection, err = s.uploadProtectionSummaryCounts(ctx, filter, limit)
	if err != nil {
		return summary, err
	}
	summary.BotProtection, err = s.botProtectionSummaryCounts(ctx, filter, limit)
	if err != nil {
		return summary, err
	}
	summary.DynamicProtection, err = s.dynamicProtectionSummaryCounts(ctx, filter, limit)
	return summary, err
}

func (s *PostgresStore) ListDynamicBans(ctx context.Context, filter model.DynamicBanFilter) ([]model.DynamicBan, error) {
	limit := normalizeLimit(filter.Pagination.Limit)
	offset := filter.Pagination.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, site_id, client_ip, ban_reason, source, source_event_id, ban_duration_sec,
			ban_remaining_sec, status, revision, created_at, expires_at, cleared_at, updated_at
		FROM dynamic_bans
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2 = '' OR client_ip = $2)
			AND ($3::bigint = 0 OR revision > $3)
		ORDER BY updated_at DESC, id DESC
		LIMIT $4 OFFSET $5`,
		filter.SiteID, filter.ClientIP, filter.MinRevision, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	items := []model.DynamicBan{}
	for rows.Next() {
		item, err := scanDynamicBan(rows)
		if err != nil {
			return nil, err
		}
		item = dynamicBanWithStatus(item, now)
		if filter.Status != "" && item.Status != filter.Status {
			continue
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) ClearDynamicBan(ctx context.Context, request model.DynamicBanClearRequest) (model.DynamicBanClearResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DynamicBanClearResult{}, err
	}
	defer tx.Rollback()
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT nextval('dynamic_ban_clear_revision_seq')`).Scan(&revision); err != nil {
		return model.DynamicBanClearResult{}, err
	}
	now := time.Now().UTC()
	status := "no-op"
	message := "dynamic ban was already cleared, expired, or not found"
	result, err := tx.ExecContext(ctx, `
		UPDATE dynamic_bans
		SET status = 'cleared', cleared_at = $1, updated_at = $1, revision = $2, ban_remaining_sec = 0
		WHERE site_id = $3 AND client_ip = $4 AND status = 'active' AND expires_at > $1`,
		now, revision, request.SiteID, request.ClientIP)
	if err != nil {
		return model.DynamicBanClearResult{}, err
	}
	if affected, _ := result.RowsAffected(); affected > 0 {
		status = "cleared"
		message = "dynamic ban clear recorded"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dynamic_ban_clears (site_id, client_ip, status, revision, actor, message, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		request.SiteID, request.ClientIP, status, revision, request.Actor, message, now); err != nil {
		return model.DynamicBanClearResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.DynamicBanClearResult{}, err
	}
	return model.DynamicBanClearResult{
		SiteID:    request.SiteID,
		ClientIP:  request.ClientIP,
		Status:    status,
		Revision:  revision,
		ClearedAt: now,
		Message:   message,
	}, nil
}

func (s *PostgresStore) ListDynamicBanClears(ctx context.Context, filter model.DynamicBanFilter) ([]model.DynamicBanClearResult, error) {
	limit := normalizeLimit(filter.Pagination.Limit)
	offset := filter.Pagination.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT site_id, client_ip, status, revision, created_at, message
		FROM dynamic_ban_clears
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2 = '' OR client_ip = $2)
			AND ($3::bigint = 0 OR revision > $3)
		ORDER BY revision ASC
		LIMIT $4 OFFSET $5`,
		filter.SiteID, filter.ClientIP, filter.MinRevision, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []model.DynamicBanClearResult{}
	for rows.Next() {
		var item model.DynamicBanClearResult
		if err := rows.Scan(&item.SiteID, &item.ClientIP, &item.Status, &item.Revision, &item.ClearedAt, &item.Message); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) projectDynamicBanEvent(ctx context.Context, item model.WAFEvent) error {
	if item.EventType != "dynamic-ban" || item.SiteID <= 0 || item.ClientIP == "" {
		return nil
	}
	duration := item.BanDurationSec
	if duration <= 0 {
		duration = item.BanRemainingSec
	}
	if duration <= 0 {
		return nil
	}
	remaining := duration
	if item.BanRemainingSec > 0 {
		remaining = item.BanRemainingSec
	}
	createdAt := item.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	expiresAt := createdAt.Add(time.Duration(remaining) * time.Second)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dynamic_bans (
			site_id, client_ip, ban_reason, source, source_event_id, ban_duration_sec,
			ban_remaining_sec, status, created_at, expires_at, cleared_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, NULL, $8)
		ON CONFLICT (site_id, client_ip) DO UPDATE SET
			ban_reason = EXCLUDED.ban_reason,
			source = EXCLUDED.source,
			source_event_id = EXCLUDED.source_event_id,
			ban_duration_sec = EXCLUDED.ban_duration_sec,
			ban_remaining_sec = EXCLUDED.ban_remaining_sec,
			status = 'active',
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at,
			cleared_at = NULL,
			updated_at = EXCLUDED.updated_at`,
		item.SiteID, item.ClientIP, item.BanReason, dynamicBanSource(item), item.ID,
		duration, remaining, createdAt, expiresAt)
	return err
}

type dynamicBanScanner interface {
	Scan(dest ...any) error
}

func scanDynamicBan(row dynamicBanScanner) (model.DynamicBan, error) {
	var item model.DynamicBan
	var clearedAt sql.NullTime
	err := row.Scan(
		&item.ID, &item.SiteID, &item.ClientIP, &item.BanReason, &item.Source, &item.SourceEventID,
		&item.BanDurationSec, &item.BanRemainingSec, &item.Status, &item.Revision,
		&item.CreatedAt, &item.ExpiresAt, &clearedAt, &item.UpdatedAt,
	)
	if clearedAt.Valid {
		item.ClearedAt = clearedAt.Time
	}
	item.Time = item.CreatedAt.Format(time.RFC3339)
	return item, err
}

func (s *PostgresStore) accessControlSummaryCounts(ctx context.Context, filter model.ObservabilitySummaryFilter, limit int) ([]model.SummaryCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT action || '|' || disposition AS key, count(*) AS count
		FROM waf_events
		WHERE module = 'access-control'
			AND action <> ''
			AND ($1::timestamptz IS NULL OR created_at >= $1)
			AND ($2::timestamptz IS NULL OR created_at <= $2)
		GROUP BY key
		ORDER BY count DESC, key ASC
		LIMIT $3`, nullableTime(filter.Since), nullableTime(filter.Until), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.SummaryCount
	for rows.Next() {
		var item model.SummaryCount
		if err := rows.Scan(&item.Key, &item.Count); err != nil {
			return nil, err
		}
		if strings.TrimSpace(item.Key) != "" {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func (s *PostgresStore) attackProtectionSummaryCounts(ctx context.Context, filter model.ObservabilitySummaryFilter, limit int) ([]model.SummaryCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT attack_type || '|' || action || '|' || disposition AS key, count(*) AS count
		FROM waf_events
		WHERE module = 'attack-protection'
			AND attack_type <> ''
			AND ($1::timestamptz IS NULL OR created_at >= $1)
			AND ($2::timestamptz IS NULL OR created_at <= $2)
		GROUP BY key
		ORDER BY count DESC, key ASC
		LIMIT $3`, nullableTime(filter.Since), nullableTime(filter.Until), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.SummaryCount
	for rows.Next() {
		var item model.SummaryCount
		if err := rows.Scan(&item.Key, &item.Count); err != nil {
			return nil, err
		}
		if strings.TrimSpace(item.Key) != "" {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func (s *PostgresStore) uploadProtectionSummaryCounts(ctx context.Context, filter model.ObservabilitySummaryFilter, limit int) ([]model.SummaryCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT action || '|' || disposition AS key, count(*) AS count
		FROM waf_events
		WHERE module = 'upload-protection'
			AND action <> ''
			AND ($1::timestamptz IS NULL OR created_at >= $1)
			AND ($2::timestamptz IS NULL OR created_at <= $2)
		GROUP BY key
		ORDER BY count DESC, key ASC
		LIMIT $3`, nullableTime(filter.Since), nullableTime(filter.Until), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.SummaryCount
	for rows.Next() {
		var item model.SummaryCount
		if err := rows.Scan(&item.Key, &item.Count); err != nil {
			return nil, err
		}
		if strings.TrimSpace(item.Key) != "" {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func (s *PostgresStore) botProtectionSummaryCounts(ctx context.Context, filter model.ObservabilitySummaryFilter, limit int) ([]model.SummaryCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT challenge_result || '|' || COALESCE(NULLIF(bot_result, ''), 'standard') || '|' || action || '|' || disposition AS key, count(*) AS count
		FROM waf_events
		WHERE module = 'bot-protection'
			AND action <> ''
			AND ($1::timestamptz IS NULL OR created_at >= $1)
			AND ($2::timestamptz IS NULL OR created_at <= $2)
		GROUP BY key
		ORDER BY count DESC, key ASC
		LIMIT $3`, nullableTime(filter.Since), nullableTime(filter.Until), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.SummaryCount
	for rows.Next() {
		var item model.SummaryCount
		if err := rows.Scan(&item.Key, &item.Count); err != nil {
			return nil, err
		}
		if strings.TrimSpace(item.Key) != "" {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func (s *PostgresStore) dynamicProtectionSummaryCounts(ctx context.Context, filter model.ObservabilitySummaryFilter, limit int) ([]model.SummaryCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT category || '|' || advanced_target || '|' || action || '|' || disposition AS key, count(*) AS count
		FROM waf_events
		WHERE module = 'dynamic-protection'
			AND action <> ''
			AND ($1::timestamptz IS NULL OR created_at >= $1)
			AND ($2::timestamptz IS NULL OR created_at <= $2)
		GROUP BY key
		ORDER BY count DESC, key ASC
		LIMIT $3`, nullableTime(filter.Since), nullableTime(filter.Until), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.SummaryCount
	for rows.Next() {
		var item model.SummaryCount
		if err := rows.Scan(&item.Key, &item.Count); err != nil {
			return nil, err
		}
		if strings.TrimSpace(item.Key) != "" {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func (s *PostgresStore) summaryCounts(ctx context.Context, table string, column string, filter model.ObservabilitySummaryFilter, limit int) ([]model.SummaryCount, error) {
	if !oneOfIdentifier(table, "access_logs", "waf_events") {
		return nil, fmt.Errorf("unsupported summary table %q", table)
	}
	if !oneOfIdentifier(column, "client_ip", "uri", "rule_id::text", "event_type", "attack_type") {
		return nil, fmt.Errorf("unsupported summary column %q", column)
	}
	query := fmt.Sprintf(`
		SELECT %s AS key, count(*) AS count
		FROM %s
		WHERE %s <> ''
			AND ($1::timestamptz IS NULL OR created_at >= $1)
			AND ($2::timestamptz IS NULL OR created_at <= $2)
		GROUP BY key
		ORDER BY count DESC, key ASC
		LIMIT $3`, column, table, column)
	rows, err := s.db.QueryContext(ctx, query, nullableTime(filter.Since), nullableTime(filter.Until), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.SummaryCount
	for rows.Next() {
		var item model.SummaryCount
		if err := rows.Scan(&item.Key, &item.Count); err != nil {
			return nil, err
		}
		if strings.TrimSpace(item.Key) != "" && item.Key != "0" {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func oneOfIdentifier(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
