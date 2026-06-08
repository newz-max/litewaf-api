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
		INSERT INTO access_logs (
			request_id, site_id, listener_port, scheme, host, method, uri, status, upstream_status,
			duration_ms, client_ip, user_agent, referer, geo_country, geo_region, geo_city,
			geo_district, geo_longitude, geo_latitude, geo_resolved, geo_source, geo_source_version,
			geo_unresolved_reason, disposition, reason_code, reason, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, COALESCE($27::timestamptz, now()))
		RETURNING id, created_at`,
		item.RequestID, item.SiteID, item.ListenerPort, item.Scheme, item.Host, item.Method, item.URI, item.Status, item.UpstreamStatus,
		item.DurationMS, item.ClientIP, item.UserAgent, item.Referer, item.GeoCountry, item.GeoRegion, item.GeoCity,
		item.GeoDistrict, item.GeoLongitude, item.GeoLatitude, item.GeoResolved, item.GeoSource, item.GeoSourceVersion,
		item.GeoUnresolvedReason, item.Disposition, item.ReasonCode, item.Reason, createdAt).
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
		SELECT id, request_id, site_id, listener_port, scheme, host, method, uri, status, upstream_status,
			duration_ms, client_ip, user_agent, referer, geo_country, geo_region, geo_city,
			geo_district, geo_longitude, geo_latitude, geo_resolved, geo_source, geo_source_version,
			geo_unresolved_reason, disposition, reason_code, reason, created_at
		FROM access_logs
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2::integer = 0 OR listener_port = $2)
			AND ($3 = '' OR scheme = $3)
			AND ($4 = '' OR host = $4)
			AND ($5 = '' OR client_ip = $5)
			AND ($6 = '' OR method = $6)
			AND ($7 = '' OR uri ILIKE '%' || $7 || '%')
			AND ($8::integer = 0 OR status = $8)
			AND ($9 = '' OR disposition = $9)
			AND ($10 = '' OR reason_code = $10)
			AND ($11::timestamptz IS NULL OR created_at >= $11)
			AND ($12::timestamptz IS NULL OR created_at <= $12)
		ORDER BY id DESC
		LIMIT $13 OFFSET $14`,
		filter.SiteID, filter.ListenerPort, filter.Scheme, filter.Host, filter.ClientIP, filter.Method, filter.URI, filter.Status, filter.Disposition,
		filter.ReasonCode, nullableTime(filter.Since), nullableTime(filter.Until), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.AccessLog
	for rows.Next() {
		var item model.AccessLog
		if err := rows.Scan(
			&item.ID, &item.RequestID, &item.SiteID, &item.ListenerPort, &item.Scheme, &item.Host, &item.Method, &item.URI, &item.Status, &item.UpstreamStatus,
			&item.DurationMS, &item.ClientIP, &item.UserAgent, &item.Referer, &item.GeoCountry, &item.GeoRegion, &item.GeoCity,
			&item.GeoDistrict, &item.GeoLongitude, &item.GeoLatitude, &item.GeoResolved, &item.GeoSource, &item.GeoSourceVersion,
			&item.GeoUnresolvedReason, &item.Disposition, &item.ReasonCode, &item.Reason, &item.CreatedAt,
		); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) ListDeniedRecords(ctx context.Context, filter model.DeniedRecordFilter) ([]model.DeniedRecord, error) {
	limit := normalizeLimit(filter.Pagination.Limit)
	offset := filter.Pagination.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			a.id, a.request_id, a.site_id, a.listener_port, a.scheme, a.host, a.method, a.uri,
			a.status, a.upstream_status, a.duration_ms, a.client_ip, a.disposition,
			a.reason_code, a.reason,
			CASE
				WHEN w.id IS NOT NULL THEN 'waf-event'
				WHEN d.id IS NOT NULL THEN 'dynamic-ban'
				WHEN a.reason_code <> '' OR a.reason <> '' THEN 'access-log'
				ELSE 'unclassified'
			END AS explanation_source,
			CASE
				WHEN w.id IS NOT NULL THEN 'request-id'
				WHEN d.id IS NOT NULL THEN 'fallback'
				ELSE 'none'
			END AS correlation_type,
			COALESCE(w.id, 0), COALESCE(w.event_type, ''), COALESCE(w.module, ''), COALESCE(w.category, ''),
			COALESCE(w.rule_id, 0), COALESCE(w.rule_name, ''), COALESCE(w.action, ''), COALESCE(w.attack_type, ''),
			COALESCE(w.summary, ''),
			COALESCE(d.ban_reason, ''), COALESCE(d.source, ''), COALESCE(d.status, ''), COALESCE(d.ban_remaining_sec, 0),
			a.created_at
		FROM access_logs a
		LEFT JOIN LATERAL (
			SELECT id, event_type, module, category, rule_id, rule_name, action, attack_type, summary
			FROM waf_events
			WHERE request_id = a.request_id AND a.request_id <> ''
			ORDER BY id DESC
			LIMIT 1
		) w ON true
		LEFT JOIN LATERAL (
			SELECT id, ban_reason, source, status, ban_remaining_sec, updated_at
			FROM dynamic_bans
			WHERE site_id = a.site_id
				AND listener_port = a.listener_port
				AND scheme = a.scheme
				AND client_ip = a.client_ip
				AND (a.created_at BETWEEN created_at AND expires_at OR (status = 'active' AND expires_at > now()))
			ORDER BY updated_at DESC, id DESC
			LIMIT 1
		) d ON w.id IS NULL
		WHERE a.disposition IN ('blocked', 'rejected')
			AND ($1::bigint = 0 OR a.site_id = $1)
			AND ($2::integer = 0 OR a.listener_port = $2)
			AND ($3 = '' OR a.scheme = $3)
			AND ($4 = '' OR a.host = $4)
			AND ($5 = '' OR a.client_ip = $5)
			AND ($6 = '' OR a.method = $6)
			AND ($7 = '' OR a.uri ILIKE '%' || $7 || '%')
			AND ($8::integer = 0 OR a.status = $8)
			AND ($9 = '' OR a.disposition = $9)
			AND ($10::timestamptz IS NULL OR a.created_at >= $10)
			AND ($11::timestamptz IS NULL OR a.created_at <= $11)
			AND ($12 = '' OR COALESCE(w.module, '') = $12)
			AND ($13 = '' OR COALESCE(w.action, '') = $13)
			AND ($14 = '' OR CASE
				WHEN w.id IS NOT NULL THEN 'waf-event'
				WHEN d.id IS NOT NULL THEN 'dynamic-ban'
				WHEN a.reason_code <> '' OR a.reason <> '' THEN 'access-log'
				ELSE 'unclassified'
			END = $14)
		ORDER BY a.id DESC
		LIMIT $15 OFFSET $16`,
		filter.SiteID, filter.ListenerPort, filter.Scheme, filter.Host, filter.ClientIP, filter.Method, filter.URI, filter.Status, filter.Disposition,
		nullableTime(filter.Since), nullableTime(filter.Until), filter.Module, filter.Action, filter.TriggerSource, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.DeniedRecord
	for rows.Next() {
		var item model.DeniedRecord
		if err := rows.Scan(
			&item.ID, &item.RequestID, &item.SiteID, &item.ListenerPort, &item.Scheme, &item.Host, &item.Method, &item.URI,
			&item.Status, &item.UpstreamStatus, &item.DurationMS, &item.ClientIP, &item.Disposition,
			&item.ReasonCode, &item.Reason, &item.ExplanationSource, &item.CorrelationType,
			&item.WAFEventID, &item.EventType, &item.Module, &item.Category, &item.RuleID, &item.RuleName, &item.Action, &item.AttackType,
			&item.Summary, &item.DynamicBanReason, &item.DynamicBanSource, &item.DynamicBanStatus, &item.DynamicBanRemainingSec,
			&item.CreatedAt,
		); err != nil {
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
			request_id, site_id, listener_port, scheme, host, event_type, rule_id, rule_type, target, action, disposition,
			client_ip, method, uri, summary, rate_limit_id,
			module, category, rule_name, attack_type, group_name, counter, window_sec,
			advanced_target, normalized_value, score, threshold, matched_rule_ids,
			body_metadata, upload_metadata, ip_access_list_id, ip_list_kind, ip_list_target,
			ban_reason, ban_duration_sec, ban_remaining_sec,
			challenge_mode, challenge_result, bot_result, bot_reason, device_signal,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, COALESCE($42::timestamptz, now()))
		RETURNING id, created_at`,
		item.RequestID, item.SiteID, item.ListenerPort, item.Scheme, item.Host, item.EventType, item.RuleID, item.RuleType, item.Target, item.Action, item.Disposition,
		item.ClientIP, item.Method, item.URI, item.Summary, item.RateLimitID,
		item.Module, item.Category, item.RuleName, item.AttackType, item.GroupName, item.Counter, item.WindowSec,
		item.AdvancedTarget, item.NormalizedValue, item.Score, item.Threshold, item.MatchedRuleIDs,
		item.BodyMetadata, item.UploadMetadata, item.IPAccessListID, item.IPListKind, item.IPListTarget,
		item.BanReason, item.BanDurationSec, item.BanRemainingSec,
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
		SELECT id, request_id, site_id, listener_port, scheme, host, event_type, rule_id, rule_type, target, action, disposition,
			client_ip, method, uri, summary, rate_limit_id,
			module, category, rule_name, attack_type, group_name, counter, window_sec,
			advanced_target, normalized_value, score, threshold, matched_rule_ids,
			body_metadata, upload_metadata, ip_access_list_id, ip_list_kind, ip_list_target,
			ban_reason, ban_duration_sec, ban_remaining_sec,
			challenge_mode, challenge_result, bot_result, bot_reason, device_signal,
			created_at
		FROM waf_events
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2::integer = 0 OR listener_port = $2)
			AND ($3 = '' OR scheme = $3)
			AND ($4 = '' OR host = $4)
			AND ($5 = '' OR client_ip = $5)
			AND ($6::bigint = 0 OR rule_id = $6)
			AND ($7 = '' OR action = $7)
			AND ($8 = '' OR disposition = $8)
			AND ($9 = '' OR event_type = $9)
			AND ($10 = '' OR module = $10)
			AND ($11 = '' OR attack_type = $11)
			AND ($12 = '' OR advanced_target = $12 OR target = $12)
			AND ($13 = '' OR challenge_result = $13)
			AND ($14::integer = 0 OR score >= $14)
			AND ($15 = '' OR advanced_target = $15)
			AND ($16 = '' OR bot_result = $16)
			AND ($17::timestamptz IS NULL OR created_at >= $17)
			AND ($18::timestamptz IS NULL OR created_at <= $18)
		ORDER BY id DESC
		LIMIT $19 OFFSET $20`,
		filter.SiteID, filter.ListenerPort, filter.Scheme, filter.Host, filter.ClientIP, filter.RuleID, filter.Action, filter.Disposition, filter.EventType,
		filter.Module, filter.AttackType, filter.AdvancedTarget, filter.ChallengeResult, filter.MinScore, filter.DynamicResult, filter.BotResult, nullableTime(filter.Since), nullableTime(filter.Until), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.WAFEvent
	for rows.Next() {
		var item model.WAFEvent
		if err := rows.Scan(
			&item.ID, &item.RequestID, &item.SiteID, &item.ListenerPort, &item.Scheme, &item.Host, &item.EventType, &item.RuleID, &item.RuleType, &item.Target, &item.Action, &item.Disposition,
			&item.ClientIP, &item.Method, &item.URI, &item.Summary, &item.RateLimitID,
			&item.Module, &item.Category, &item.RuleName, &item.AttackType, &item.GroupName, &item.Counter, &item.WindowSec,
			&item.AdvancedTarget, &item.NormalizedValue, &item.Score, &item.Threshold, &item.MatchedRuleIDs,
			&item.BodyMetadata, &item.UploadMetadata, &item.IPAccessListID, &item.IPListKind, &item.IPListTarget,
			&item.BanReason, &item.BanDurationSec, &item.BanRemainingSec,
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
	summary.IPAccessList, err = s.ipAccessListSummaryCounts(ctx, filter, limit)
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
		SELECT id, site_id, listener_port, scheme, client_ip, ban_reason, source, source_event_id, ban_duration_sec,
			ban_remaining_sec, status, revision, created_at, expires_at, cleared_at, updated_at
		FROM dynamic_bans
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2 = '' OR client_ip = $2)
			AND ($3::bigint = 0 OR revision > $3)
			AND ($4::integer = 0 OR listener_port = $4)
			AND ($5 = '' OR scheme = $5)
		ORDER BY updated_at DESC, id DESC
		LIMIT $6 OFFSET $7`,
		filter.SiteID, filter.ClientIP, filter.MinRevision, filter.ListenerPort, filter.Scheme, limit, offset)
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
		INSERT INTO dynamic_ban_clears (site_id, listener_port, scheme, client_ip, status, revision, actor, message, created_at)
		SELECT site_id, listener_port, scheme, client_ip, $3, $4, $5, $6, $7
		FROM dynamic_bans
		WHERE site_id = $1 AND client_ip = $2
		UNION ALL
		SELECT $1, 0, '', $2, $3, $4, $5, $6, $7
		WHERE NOT EXISTS (SELECT 1 FROM dynamic_bans WHERE site_id = $1 AND client_ip = $2)`,
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
		SELECT site_id, listener_port, scheme, client_ip, status, revision, created_at, message
		FROM dynamic_ban_clears
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2 = '' OR client_ip = $2)
			AND ($3::bigint = 0 OR revision > $3)
			AND ($4::integer = 0 OR listener_port = $4)
			AND ($5 = '' OR scheme = $5)
		ORDER BY revision ASC
		LIMIT $6 OFFSET $7`,
		filter.SiteID, filter.ClientIP, filter.MinRevision, filter.ListenerPort, filter.Scheme, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []model.DynamicBanClearResult{}
	for rows.Next() {
		var item model.DynamicBanClearResult
		if err := rows.Scan(&item.SiteID, &item.ListenerPort, &item.Scheme, &item.ClientIP, &item.Status, &item.Revision, &item.ClearedAt, &item.Message); err != nil {
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
			site_id, listener_port, scheme, client_ip, ban_reason, source, source_event_id, ban_duration_sec,
			ban_remaining_sec, status, created_at, expires_at, cleared_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10, NULL, $9)
		ON CONFLICT (site_id, listener_port, scheme, client_ip) DO UPDATE SET
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
		item.SiteID, item.ListenerPort, item.Scheme, item.ClientIP, item.BanReason, dynamicBanSource(item), item.ID,
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
		&item.ID, &item.SiteID, &item.ListenerPort, &item.Scheme, &item.ClientIP, &item.BanReason, &item.Source, &item.SourceEventID,
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

func (s *PostgresStore) ipAccessListSummaryCounts(ctx context.Context, filter model.ObservabilitySummaryFilter, limit int) ([]model.SummaryCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(NULLIF(ip_list_kind, ''), action) || '|' || ip_list_target || '|' || action || '|' || disposition AS key, count(*) AS count
		FROM waf_events
		WHERE module = 'ip-access-list'
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
