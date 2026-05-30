package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"litewaf-api/internal/model"
)

type MemoryStore struct {
	mu            sync.RWMutex
	nextSiteID    int64
	nextRuleID    int64
	nextPolicyID  int64
	nextPublishID int64
	nextUserID    int64
	nextAuditID   int64
	nextAccessID  int64
	nextRateID    int64
	sites         map[int64]model.Site
	rules         map[int64]model.Rule
	policies      map[int64]model.Policy
	publishes     map[int64]model.PublishRecord
	users         map[int64]model.User
	audits        map[int64]model.AuditLog
	accessLists   map[int64]model.AccessListEntry
	rateLimits    map[int64]model.RateLimitRule
}

func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		nextSiteID:    1,
		nextRuleID:    1,
		nextPolicyID:  1,
		nextPublishID: 1,
		nextUserID:    1,
		nextAuditID:   1,
		nextAccessID:  1,
		nextRateID:    1,
		sites:         map[int64]model.Site{},
		rules:         map[int64]model.Rule{},
		policies:      map[int64]model.Policy{},
		publishes:     map[int64]model.PublishRecord{},
		users:         map[int64]model.User{},
		audits:        map[int64]model.AuditLog{},
		accessLists:   map[int64]model.AccessListEntry{},
		rateLimits:    map[int64]model.RateLimitRule{},
	}
	store.seedRules()
	return store
}

func (s *MemoryStore) Ping(context.Context) error { return nil }
func (s *MemoryStore) Close() error               { return nil }

func (s *MemoryStore) seedRules() {
	now := time.Now().UTC()
	for _, rule := range []model.Rule{
		{Name: "MVP SQLi baseline", Type: "sqli", Target: "args", Action: "block", Expression: "(?i)(union\\s+select|or\\s+1=1|sleep\\s*\\()", Score: 80, Enabled: true},
		{Name: "MVP XSS baseline", Type: "xss", Target: "args", Action: "block", Expression: "(?i)(<script|javascript:|onerror\\s*=)", Score: 80, Enabled: true},
	} {
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
