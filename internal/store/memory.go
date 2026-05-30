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
	sites         map[int64]model.Site
	rules         map[int64]model.Rule
	policies      map[int64]model.Policy
	publishes     map[int64]model.PublishRecord
}

func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		nextSiteID:    1,
		nextRuleID:    1,
		nextPolicyID:  1,
		nextPublishID: 1,
		sites:         map[int64]model.Site{},
		rules:         map[int64]model.Rule{},
		policies:      map[int64]model.Policy{},
		publishes:     map[int64]model.PublishRecord{},
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
