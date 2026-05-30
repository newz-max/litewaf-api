package store

import (
	"context"
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
		INSERT INTO waf_events (request_id, site_id, event_type, rule_id, rule_type, target, action, disposition, client_ip, method, uri, summary, access_list_id, rate_limit_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, COALESCE($15::timestamptz, now()))
		RETURNING id, created_at`,
		item.RequestID, item.SiteID, item.EventType, item.RuleID, item.RuleType, item.Target, item.Action, item.Disposition, item.ClientIP, item.Method, item.URI, item.Summary, item.AccessListID, item.RateLimitID, createdAt).
		Scan(&item.ID, &item.CreatedAt)
	item.Time = item.CreatedAt.Format(time.RFC3339)
	return item, err
}

func (s *PostgresStore) ListWAFEvents(ctx context.Context, filter model.WAFEventFilter) ([]model.WAFEvent, error) {
	limit := normalizeLimit(filter.Pagination.Limit)
	offset := filter.Pagination.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, request_id, site_id, event_type, rule_id, rule_type, target, action, disposition, client_ip, method, uri, summary, access_list_id, rate_limit_id, created_at
		FROM waf_events
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2 = '' OR client_ip = $2)
			AND ($3::bigint = 0 OR rule_id = $3)
			AND ($4 = '' OR action = $4)
			AND ($5 = '' OR disposition = $5)
			AND ($6 = '' OR event_type = $6)
			AND ($7::timestamptz IS NULL OR created_at >= $7)
			AND ($8::timestamptz IS NULL OR created_at <= $8)
		ORDER BY id DESC
		LIMIT $9 OFFSET $10`,
		filter.SiteID, filter.ClientIP, filter.RuleID, filter.Action, filter.Disposition, filter.EventType,
		nullableTime(filter.Since), nullableTime(filter.Until), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.WAFEvent
	for rows.Next() {
		var item model.WAFEvent
		if err := rows.Scan(&item.ID, &item.RequestID, &item.SiteID, &item.EventType, &item.RuleID, &item.RuleType, &item.Target, &item.Action, &item.Disposition, &item.ClientIP, &item.Method, &item.URI, &item.Summary, &item.AccessListID, &item.RateLimitID, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetObservabilitySummary(ctx context.Context, filter model.ObservabilitySummaryFilter) (model.ObservabilitySummary, error) {
	summary := model.ObservabilitySummary{}
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
			count(*) FILTER (WHERE event_type = 'rate-limit' OR rate_limit_id > 0)
		FROM waf_events
		WHERE ($1::timestamptz IS NULL OR created_at >= $1)
			AND ($2::timestamptz IS NULL OR created_at <= $2)`,
		nullableTime(filter.Since), nullableTime(filter.Until)).
		Scan(&summary.WAFMatches, &eventBlocked, &eventRateLimited); err != nil {
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
	return summary, err
}

func (s *PostgresStore) summaryCounts(ctx context.Context, table string, column string, filter model.ObservabilitySummaryFilter, limit int) ([]model.SummaryCount, error) {
	if !oneOfIdentifier(table, "access_logs", "waf_events") {
		return nil, fmt.Errorf("unsupported summary table %q", table)
	}
	if !oneOfIdentifier(column, "client_ip", "uri", "rule_id::text", "event_type") {
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
