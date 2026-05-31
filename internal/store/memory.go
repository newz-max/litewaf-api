package store

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"litewaf-api/internal/defaults"
	"litewaf-api/internal/model"
)

type MemoryStore struct {
	mu              sync.RWMutex
	nextSiteID      int64
	nextRuleID      int64
	nextPolicyID    int64
	nextPublishID   int64
	nextUserID      int64
	nextAuditID     int64
	nextAccessID    int64
	nextRateID      int64
	nextAccessLogID int64
	nextWAFEventID  int64
	sites           map[int64]model.Site
	rules           map[int64]model.Rule
	policies        map[int64]model.Policy
	publishes       map[int64]model.PublishRecord
	users           map[int64]model.User
	audits          map[int64]model.AuditLog
	accessLists     map[int64]model.AccessListEntry
	rateLimits      map[int64]model.RateLimitRule
	accessLogs      map[int64]model.AccessLog
	wafEvents       map[int64]model.WAFEvent
}

func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		nextSiteID:      1,
		nextRuleID:      1,
		nextPolicyID:    1,
		nextPublishID:   1,
		nextUserID:      1,
		nextAuditID:     1,
		nextAccessID:    1,
		nextRateID:      1,
		nextAccessLogID: 1,
		nextWAFEventID:  1,
		sites:           map[int64]model.Site{},
		rules:           map[int64]model.Rule{},
		policies:        map[int64]model.Policy{},
		publishes:       map[int64]model.PublishRecord{},
		users:           map[int64]model.User{},
		audits:          map[int64]model.AuditLog{},
		accessLists:     map[int64]model.AccessListEntry{},
		rateLimits:      map[int64]model.RateLimitRule{},
		accessLogs:      map[int64]model.AccessLog{},
		wafEvents:       map[int64]model.WAFEvent{},
	}
	store.seedRules()
	return store
}

func (s *MemoryStore) Ping(context.Context) error { return nil }
func (s *MemoryStore) Close() error               { return nil }

func (s *MemoryStore) seedRules() {
	now := time.Now().UTC()
	for _, rule := range defaults.DefaultRules {
		rule.ID = s.nextRuleID
		rule.CreatedAt = now
		rule.UpdatedAt = now
		s.rules[rule.ID] = rule
		s.nextRuleID++
	}
}

func (s *MemoryStore) ListSites(context.Context) ([]model.Site, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.Site, 0, len(s.sites))
	for _, item := range s.sites {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetSite(_ context.Context, id int64) (model.Site, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.sites[id]
	if !ok {
		return model.Site{}, ErrNotFound
	}
	return item, nil
}

func (s *MemoryStore) CreateSite(_ context.Context, site model.Site) (model.Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	site.ID = s.nextSiteID
	site.CreatedAt = now
	site.UpdatedAt = now
	s.sites[site.ID] = site
	s.nextSiteID++
	return site, nil
}

func (s *MemoryStore) UpdateSite(_ context.Context, id int64, site model.Site) (model.Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.sites[id]
	if !ok {
		return model.Site{}, ErrNotFound
	}
	site.ID = id
	site.CreatedAt = existing.CreatedAt
	site.UpdatedAt = time.Now().UTC()
	s.sites[id] = site
	return site, nil
}

func (s *MemoryStore) DeleteSite(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sites[id]; !ok {
		return ErrNotFound
	}
	delete(s.sites, id)
	return nil
}

func (s *MemoryStore) ListRules(context.Context) ([]model.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.Rule, 0, len(s.rules))
	for _, item := range s.rules {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetRule(_ context.Context, id int64) (model.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.rules[id]
	if !ok {
		return model.Rule{}, ErrNotFound
	}
	return item, nil
}

func (s *MemoryStore) CreateRule(_ context.Context, rule model.Rule) (model.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	rule.ID = s.nextRuleID
	rule.CreatedAt = now
	rule.UpdatedAt = now
	s.rules[rule.ID] = rule
	s.nextRuleID++
	return rule, nil
}

func (s *MemoryStore) UpdateRule(_ context.Context, id int64, rule model.Rule) (model.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.rules[id]
	if !ok {
		return model.Rule{}, ErrNotFound
	}
	rule.ID = id
	rule.CreatedAt = existing.CreatedAt
	rule.UpdatedAt = time.Now().UTC()
	s.rules[id] = rule
	return rule, nil
}

func (s *MemoryStore) DeleteRule(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[id]; !ok {
		return ErrNotFound
	}
	delete(s.rules, id)
	return nil
}

func (s *MemoryStore) ListPolicies(context.Context) ([]model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.Policy, 0, len(s.policies))
	for _, item := range s.policies {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetPolicy(_ context.Context, id int64) (model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.policies[id]
	if !ok {
		return model.Policy{}, ErrNotFound
	}
	return item, nil
}

func (s *MemoryStore) CreatePolicy(_ context.Context, policy model.Policy) (model.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.bindingsExistLocked(policy) {
		return model.Policy{}, ErrNotFound
	}
	now := time.Now().UTC()
	policy.ID = s.nextPolicyID
	policy.CreatedAt = now
	policy.UpdatedAt = now
	policy.SiteIDs = cloneIDs(policy.SiteIDs)
	policy.RuleIDs = cloneIDs(policy.RuleIDs)
	s.policies[policy.ID] = policy
	s.nextPolicyID++
	return policy, nil
}

func (s *MemoryStore) UpdatePolicy(_ context.Context, id int64, policy model.Policy) (model.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.policies[id]
	if !ok {
		return model.Policy{}, ErrNotFound
	}
	if !s.bindingsExistLocked(policy) {
		return model.Policy{}, ErrNotFound
	}
	policy.ID = id
	policy.CreatedAt = existing.CreatedAt
	policy.UpdatedAt = time.Now().UTC()
	policy.SiteIDs = cloneIDs(policy.SiteIDs)
	policy.RuleIDs = cloneIDs(policy.RuleIDs)
	s.policies[id] = policy
	return policy, nil
}

func (s *MemoryStore) DeletePolicy(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[id]; !ok {
		return ErrNotFound
	}
	delete(s.policies, id)
	return nil
}

func (s *MemoryStore) ListPublishRecords(context.Context) ([]model.PublishRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.PublishRecord, 0, len(s.publishes))
	for _, item := range s.publishes {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return items, nil
}

func (s *MemoryStore) CreatePublishRecord(_ context.Context, record model.PublishRecord) (model.PublishRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record.ID = s.nextPublishID
	record.CreatedAt = time.Now().UTC()
	record.Time = record.CreatedAt.Format(time.RFC3339)
	s.publishes[record.ID] = record
	s.nextPublishID++
	return record, nil
}

func (s *MemoryStore) NextPublishVersion(context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.publishes) + 1), nil
}

func (s *MemoryStore) GetPublishRecordByVersion(_ context.Context, version string) (model.PublishRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.publishes {
		if item.Version == version {
			return item, nil
		}
	}
	return model.PublishRecord{}, ErrNotFound
}

func (s *MemoryStore) GetUserByUsername(_ context.Context, username string) (model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.users {
		if item.Username == username {
			return item, nil
		}
	}
	return model.User{}, ErrNotFound
}

func (s *MemoryStore) EnsureUser(_ context.Context, user model.User) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.users {
		if existing.Username == user.Username {
			user.ID = id
			user.CreatedAt = existing.CreatedAt
			user.UpdatedAt = time.Now().UTC()
			s.users[id] = user
			return user, nil
		}
	}
	now := time.Now().UTC()
	user.ID = s.nextUserID
	user.CreatedAt = now
	user.UpdatedAt = now
	s.users[user.ID] = user
	s.nextUserID++
	return user, nil
}

func (s *MemoryStore) ListAuditLogs(_ context.Context, filter model.AuditLogFilter) ([]model.AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.AuditLog, 0, len(s.audits))
	for _, item := range s.audits {
		if auditMatches(item, filter) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return items, nil
}

func (s *MemoryStore) CreateAuditLog(_ context.Context, item model.AuditLog) (model.AuditLog, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item.ID = s.nextAuditID
	item.CreatedAt = time.Now().UTC()
	item.Time = item.CreatedAt.Format(time.RFC3339)
	s.audits[item.ID] = item
	s.nextAuditID++
	return item, nil
}

func (s *MemoryStore) CreateAccessLog(_ context.Context, item model.AccessLog) (model.AccessLog, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item.ID = s.nextAccessLogID
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	item.Time = item.CreatedAt.Format(time.RFC3339)
	s.accessLogs[item.ID] = item
	s.nextAccessLogID++
	return item, nil
}

func (s *MemoryStore) ListAccessLogs(_ context.Context, filter model.AccessLogFilter) ([]model.AccessLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.AccessLog, 0, len(s.accessLogs))
	for _, item := range s.accessLogs {
		if accessLogMatches(item, filter) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return paginate(items, filter.Pagination), nil
}

func (s *MemoryStore) CreateWAFEvent(_ context.Context, item model.WAFEvent) (model.WAFEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item.ID = s.nextWAFEventID
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	item.Time = item.CreatedAt.Format(time.RFC3339)
	s.wafEvents[item.ID] = item
	s.nextWAFEventID++
	return item, nil
}

func (s *MemoryStore) ListWAFEvents(_ context.Context, filter model.WAFEventFilter) ([]model.WAFEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.WAFEvent, 0, len(s.wafEvents))
	for _, item := range s.wafEvents {
		if wafEventMatches(item, filter) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return paginate(items, filter.Pagination), nil
}

func (s *MemoryStore) GetObservabilitySummary(_ context.Context, filter model.ObservabilitySummaryFilter) (model.ObservabilitySummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := normalizeSummaryLimit(filter.Limit)
	summary := model.ObservabilitySummary{}
	ipCounts := map[string]int64{}
	uriCounts := map[string]int64{}
	ruleCounts := map[string]int64{}
	typeCounts := map[string]int64{}
	for _, item := range s.accessLogs {
		if !summaryTimeMatches(item.CreatedAt, filter.Since, filter.Until) {
			continue
		}
		summary.Requests++
		if item.Disposition == "blocked" || item.Disposition == "rejected" {
			summary.BlockedRequests++
		}
		if item.Disposition == "rate-limited" {
			summary.RateLimited++
		}
		increment(ipCounts, item.ClientIP)
		increment(uriCounts, item.URI)
	}
	for _, item := range s.wafEvents {
		if !summaryTimeMatches(item.CreatedAt, filter.Since, filter.Until) {
			continue
		}
		summary.WAFMatches++
		if item.EventType == "rate-limit" || item.RateLimitID > 0 {
			summary.RateLimited++
		}
		switch item.EventType {
		case "score-threshold":
			summary.ScoreBlocks++
		case "body-inspection":
			summary.BodyDetections++
		case "upload-inspection":
			summary.UploadDetections++
		case "dynamic-ban":
			summary.DynamicBans++
		}
		switch item.AdvancedTarget {
		case "body", "body_json", "body_form":
			summary.BodyDetections++
		case "upload", "upload_filename", "upload_extension", "upload_mime", "upload_size":
			summary.UploadDetections++
		}
		if item.Disposition == "blocked" || item.Disposition == "rejected" {
			summary.BlockedRequests++
		}
		if item.RuleID > 0 {
			increment(ruleCounts, strconvFormatInt(item.RuleID))
		} else if item.RuleName != "" {
			increment(ruleCounts, item.RuleName)
		}
		increment(typeCounts, item.EventType)
	}
	summary.TopIPs = topCounts(ipCounts, limit)
	summary.TopURIs = topCounts(uriCounts, limit)
	summary.TopRules = topCounts(ruleCounts, limit)
	summary.AttackTypes = topCounts(typeCounts, limit)
	return summary, nil
}

func (s *MemoryStore) ListAccessListEntries(context.Context) ([]model.AccessListEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.AccessListEntry, 0, len(s.accessLists))
	for _, item := range s.accessLists {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetAccessListEntry(_ context.Context, id int64) (model.AccessListEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.accessLists[id]
	if !ok {
		return model.AccessListEntry{}, ErrNotFound
	}
	return item, nil
}

func (s *MemoryStore) CreateAccessListEntry(_ context.Context, item model.AccessListEntry) (model.AccessListEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextAccessID
	item.CreatedAt = now
	item.UpdatedAt = now
	s.accessLists[item.ID] = item
	s.nextAccessID++
	return item, nil
}

func (s *MemoryStore) UpdateAccessListEntry(_ context.Context, id int64, item model.AccessListEntry) (model.AccessListEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.accessLists[id]
	if !ok {
		return model.AccessListEntry{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	s.accessLists[id] = item
	return item, nil
}

func (s *MemoryStore) DeleteAccessListEntry(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accessLists[id]; !ok {
		return ErrNotFound
	}
	delete(s.accessLists, id)
	return nil
}

func (s *MemoryStore) ListRateLimitRules(context.Context) ([]model.RateLimitRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RateLimitRule, 0, len(s.rateLimits))
	for _, item := range s.rateLimits {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetRateLimitRule(_ context.Context, id int64) (model.RateLimitRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.rateLimits[id]
	if !ok {
		return model.RateLimitRule{}, ErrNotFound
	}
	return item, nil
}

func (s *MemoryStore) CreateRateLimitRule(_ context.Context, item model.RateLimitRule) (model.RateLimitRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextRateID
	item.CreatedAt = now
	item.UpdatedAt = now
	s.rateLimits[item.ID] = item
	s.nextRateID++
	return item, nil
}

func (s *MemoryStore) UpdateRateLimitRule(_ context.Context, id int64, item model.RateLimitRule) (model.RateLimitRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.rateLimits[id]
	if !ok {
		return model.RateLimitRule{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	s.rateLimits[id] = item
	return item, nil
}

func (s *MemoryStore) DeleteRateLimitRule(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rateLimits[id]; !ok {
		return ErrNotFound
	}
	delete(s.rateLimits, id)
	return nil
}

func auditMatches(item model.AuditLog, filter model.AuditLogFilter) bool {
	if filter.Actor != "" && item.Actor != filter.Actor {
		return false
	}
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.ResourceType != "" && item.ResourceType != filter.ResourceType {
		return false
	}
	if filter.Result != "" && item.Result != filter.Result {
		return false
	}
	if !filter.Since.IsZero() && item.CreatedAt.Before(filter.Since) {
		return false
	}
	if !filter.Until.IsZero() && item.CreatedAt.After(filter.Until) {
		return false
	}
	return true
}

func accessLogMatches(item model.AccessLog, filter model.AccessLogFilter) bool {
	if filter.SiteID > 0 && item.SiteID != filter.SiteID {
		return false
	}
	if filter.Host != "" && item.Host != filter.Host {
		return false
	}
	if filter.ClientIP != "" && item.ClientIP != filter.ClientIP {
		return false
	}
	if filter.Method != "" && item.Method != filter.Method {
		return false
	}
	if filter.URI != "" && !stringsContains(item.URI, filter.URI) {
		return false
	}
	if filter.Status > 0 && item.Status != filter.Status {
		return false
	}
	if filter.Disposition != "" && item.Disposition != filter.Disposition {
		return false
	}
	return summaryTimeMatches(item.CreatedAt, filter.Since, filter.Until)
}

func wafEventMatches(item model.WAFEvent, filter model.WAFEventFilter) bool {
	if filter.SiteID > 0 && item.SiteID != filter.SiteID {
		return false
	}
	if filter.ClientIP != "" && item.ClientIP != filter.ClientIP {
		return false
	}
	if filter.RuleID > 0 && item.RuleID != filter.RuleID {
		return false
	}
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.Disposition != "" && item.Disposition != filter.Disposition {
		return false
	}
	if filter.EventType != "" && item.EventType != filter.EventType {
		return false
	}
	if filter.AdvancedTarget != "" && item.AdvancedTarget != filter.AdvancedTarget && item.Target != filter.AdvancedTarget {
		return false
	}
	if filter.MinScore > 0 && item.Score < filter.MinScore {
		return false
	}
	return summaryTimeMatches(item.CreatedAt, filter.Since, filter.Until)
}

func summaryTimeMatches(createdAt time.Time, since time.Time, until time.Time) bool {
	if !since.IsZero() && createdAt.Before(since) {
		return false
	}
	if !until.IsZero() && createdAt.After(until) {
		return false
	}
	return true
}

func paginate[T any](items []T, pagination model.Pagination) []T {
	offset := pagination.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return []T{}
	}
	limit := normalizeLimit(pagination.Limit)
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 500 {
		return 500
	}
	return limit
}

func normalizeSummaryLimit(limit int) int {
	if limit <= 0 {
		return 10
	}
	if limit > 50 {
		return 50
	}
	return limit
}

func increment(counts map[string]int64, key string) {
	if key == "" {
		return
	}
	counts[key]++
}

func topCounts(counts map[string]int64, limit int) []model.SummaryCount {
	items := make([]model.SummaryCount, 0, len(counts))
	for key, count := range counts {
		items = append(items, model.SummaryCount{Key: key, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Key < items[j].Key
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func strconvFormatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}

func stringsContains(value string, substr string) bool {
	return strings.Contains(value, substr)
}

func (s *MemoryStore) bindingsExistLocked(policy model.Policy) bool {
	for _, id := range policy.SiteIDs {
		if _, ok := s.sites[id]; !ok {
			return false
		}
	}
	for _, id := range policy.RuleIDs {
		if _, ok := s.rules[id]; !ok {
			return false
		}
	}
	return true
}

func cloneIDs(ids []int64) []int64 {
	if ids == nil {
		return []int64{}
	}
	out := make([]int64, len(ids))
	copy(out, ids)
	return out
}
