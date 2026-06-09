package store

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/defaults"
	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
)

type MemoryStore struct {
	mu                        sync.RWMutex
	nextSiteID                int64
	nextApplicationID         int64
	nextApplicationHostID     int64
	nextApplicationListenerID int64
	nextApplicationUpstreamID int64
	nextCertificateID         int64
	nextRuleID                int64
	nextPolicyID              int64
	nextPublishID             int64
	nextUserID                int64
	nextAuditID               int64
	nextIPAccessListID        int64
	nextRateID                int64
	nextUploadID              int64
	nextBotID                 int64
	nextDynamicID             int64
	nextProtectionRuleID      int64
	nextCatalogID             int64
	nextCatalogPackageID      int64
	nextTrustKeyID            int64
	nextProviderID            int64
	nextProviderPackageID     int64
	nextAccountSourceID       int64
	nextContributionID        int64
	nextPushAttemptID         int64
	nextReviewQueueID         int64
	nextFeedbackID            int64
	nextSuggestionID          int64
	nextAccessLogID           int64
	nextWAFEventID            int64
	nextDynamicBanID          int64
	nextDynamicBanRevision    int64
	sites                     map[int64]model.Site
	applications              map[int64]model.Application
	certificates              map[int64]model.Certificate
	rules                     map[int64]model.Rule
	policies                  map[int64]model.Policy
	publishes                 map[int64]model.PublishRecord
	users                     map[int64]model.User
	audits                    map[int64]model.AuditLog
	ipAccessLists             map[int64]model.IPAccessListEntry
	rateLimits                map[int64]model.RateLimitRule
	uploadRules               map[int64]model.UploadProtectionRule
	botRules                  map[int64]model.BotProtectionRule
	dynamicRules              map[int64]model.DynamicProtectionRule
	protectionRules           map[int64]model.ProtectionRule
	catalogSources            map[int64]model.RuleCatalogSource
	catalogPackages           map[int64]model.RuleCatalogPackage
	trustKeys                 map[int64]model.RuleTrustKey
	providers                 map[int64]model.RuleProviderAdapter
	providerSecrets           map[int64]string
	providerPackages          map[int64]model.RuleProviderPackage
	accountSources            map[int64]model.RuleCommunityAccountSource
	accountSecrets            map[int64]string
	contributionTargets       map[int64]model.RuleContributionTarget
	contributionSecrets       map[int64]string
	pushAttempts              map[int64]model.RuleContributionPushAttempt
	reviewQueue               map[int64]model.RuleReviewQueueItem
	feedback                  map[int64]model.RuleFeedback
	feedbackSuggestions       map[int64]model.RuleFeedbackSuggestion
	accessLogs                map[int64]model.AccessLog
	wafEvents                 map[int64]model.WAFEvent
	dynamicBans               map[string]model.DynamicBan
	dynamicBanClears          map[string]model.DynamicBanClearResult
}

func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		nextSiteID:                1,
		nextApplicationID:         1,
		nextApplicationHostID:     1,
		nextApplicationListenerID: 1,
		nextApplicationUpstreamID: 1,
		nextCertificateID:         1,
		nextRuleID:                1,
		nextPolicyID:              1,
		nextPublishID:             1,
		nextUserID:                1,
		nextAuditID:               1,
		nextIPAccessListID:        1,
		nextRateID:                1,
		nextUploadID:              1,
		nextBotID:                 1,
		nextDynamicID:             1,
		nextProtectionRuleID:      1,
		nextCatalogID:             1,
		nextCatalogPackageID:      1,
		nextTrustKeyID:            1,
		nextProviderID:            1,
		nextProviderPackageID:     1,
		nextAccountSourceID:       1,
		nextContributionID:        1,
		nextPushAttemptID:         1,
		nextReviewQueueID:         1,
		nextFeedbackID:            1,
		nextSuggestionID:          1,
		nextAccessLogID:           1,
		nextWAFEventID:            1,
		nextDynamicBanID:          1,
		nextDynamicBanRevision:    1,
		sites:                     map[int64]model.Site{},
		applications:              map[int64]model.Application{},
		certificates:              map[int64]model.Certificate{},
		rules:                     map[int64]model.Rule{},
		policies:                  map[int64]model.Policy{},
		publishes:                 map[int64]model.PublishRecord{},
		users:                     map[int64]model.User{},
		audits:                    map[int64]model.AuditLog{},
		ipAccessLists:             map[int64]model.IPAccessListEntry{},
		rateLimits:                map[int64]model.RateLimitRule{},
		uploadRules:               map[int64]model.UploadProtectionRule{},
		botRules:                  map[int64]model.BotProtectionRule{},
		dynamicRules:              map[int64]model.DynamicProtectionRule{},
		protectionRules:           map[int64]model.ProtectionRule{},
		catalogSources:            map[int64]model.RuleCatalogSource{},
		catalogPackages:           map[int64]model.RuleCatalogPackage{},
		trustKeys:                 map[int64]model.RuleTrustKey{},
		providers:                 map[int64]model.RuleProviderAdapter{},
		providerSecrets:           map[int64]string{},
		providerPackages:          map[int64]model.RuleProviderPackage{},
		accountSources:            map[int64]model.RuleCommunityAccountSource{},
		accountSecrets:            map[int64]string{},
		contributionTargets:       map[int64]model.RuleContributionTarget{},
		contributionSecrets:       map[int64]string{},
		pushAttempts:              map[int64]model.RuleContributionPushAttempt{},
		reviewQueue:               map[int64]model.RuleReviewQueueItem{},
		feedback:                  map[int64]model.RuleFeedback{},
		feedbackSuggestions:       map[int64]model.RuleFeedbackSuggestion{},
		accessLogs:                map[int64]model.AccessLog{},
		wafEvents:                 map[int64]model.WAFEvent{},
		dynamicBans:               map[string]model.DynamicBan{},
		dynamicBanClears:          map[string]model.DynamicBanClearResult{},
	}
	store.seedRules()
	return store
}

func (s *MemoryStore) Ping(context.Context) error { return nil }
func (s *MemoryStore) Close() error               { return nil }

func (s *MemoryStore) seedRules() {
	now := time.Now().UTC()
	for _, rule := range defaults.DefaultRules {
		rule = attackmeta.NormalizeRule(rule)
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

func (s *MemoryStore) ListApplications(context.Context) ([]model.Application, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.Application, 0, len(s.applications))
	for _, item := range s.applications {
		items = append(items, cloneApplication(item))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetApplication(_ context.Context, id int64) (model.Application, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.applications[id]
	if !ok {
		return model.Application{}, ErrNotFound
	}
	return cloneApplication(item), nil
}

func (s *MemoryStore) CreateApplication(_ context.Context, app model.Application) (model.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	model.NormalizeApplication(&app)
	if err := model.ValidateApplication(app, s.certificateExistsLocked); err != nil {
		return model.Application{}, err
	}
	now := time.Now().UTC()
	app.ID = s.nextApplicationID
	app.CreatedAt = now
	app.UpdatedAt = now
	s.nextApplicationID++
	s.assignApplicationChildIDsLocked(&app)
	s.applications[app.ID] = cloneApplication(app)
	return cloneApplication(app), nil
}

func (s *MemoryStore) UpdateApplication(_ context.Context, id int64, app model.Application) (model.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.applications[id]
	if !ok {
		return model.Application{}, ErrNotFound
	}
	model.NormalizeApplication(&app)
	if err := model.ValidateApplication(app, s.certificateExistsLocked); err != nil {
		return model.Application{}, err
	}
	app.ID = id
	app.CreatedAt = existing.CreatedAt
	app.UpdatedAt = time.Now().UTC()
	s.assignApplicationChildIDsLocked(&app)
	s.applications[id] = cloneApplication(app)
	return cloneApplication(app), nil
}

func (s *MemoryStore) DeleteApplication(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.applications[id]; !ok {
		return ErrNotFound
	}
	delete(s.applications, id)
	return nil
}

func (s *MemoryStore) ListCertificates(context.Context) ([]model.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.Certificate, 0, len(s.certificates))
	for _, item := range s.certificates {
		items = append(items, cloneCertificate(item))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetCertificate(_ context.Context, id int64) (model.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.certificates[id]
	if !ok {
		return model.Certificate{}, ErrNotFound
	}
	return cloneCertificate(item), nil
}

func (s *MemoryStore) CreateCertificate(_ context.Context, cert model.Certificate) (model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := model.ValidateCertificate(cert); err != nil {
		return model.Certificate{}, err
	}
	now := time.Now().UTC()
	cert.ID = s.nextCertificateID
	cert.CreatedAt = now
	cert.UpdatedAt = now
	cert.Domains = cloneStrings(cert.Domains)
	s.certificates[cert.ID] = cloneCertificate(cert)
	s.nextCertificateID++
	return cloneCertificate(cert), nil
}

func (s *MemoryStore) DeleteCertificate(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.certificates[id]; !ok {
		return ErrNotFound
	}
	if s.certificateInUseLocked(id) {
		return errors.New("certificate is used by enabled application listeners")
	}
	delete(s.certificates, id)
	return nil
}

func (s *MemoryStore) CertificateInUse(_ context.Context, id int64) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.certificates[id]; !ok {
		return false, ErrNotFound
	}
	return s.certificateInUseLocked(id), nil
}

func (s *MemoryStore) ListRules(context.Context) ([]model.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.Rule, 0, len(s.rules))
	for _, item := range s.rules {
		item = attackmeta.NormalizeRule(item)
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
	return attackmeta.NormalizeRule(item), nil
}

func (s *MemoryStore) CreateRule(_ context.Context, rule model.Rule) (model.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	rule = attackmeta.NormalizeRule(rule)
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
	rule = attackmeta.NormalizeRule(rule)
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
		items = append(items, model.AttachPublishActivation(item))
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
	record = model.AttachPublishActivation(record)
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
			return model.AttachPublishActivation(item), nil
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

func (s *MemoryStore) ListDeniedRecords(_ context.Context, filter model.DeniedRecordFilter) ([]model.DeniedRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	items := make([]model.DeniedRecord, 0)
	for _, item := range s.accessLogs {
		if !accessLogMatchesDeniedFilter(item, filter) {
			continue
		}
		record := deniedRecordFromAccessLog(item)
		if event, ok := s.findWAFEventForAccessLogLocked(item); ok {
			record = deniedRecordWithWAFEvent(record, event)
		} else if ban, ok := s.findDynamicBanForAccessLogLocked(item, now); ok {
			record = deniedRecordWithDynamicBan(record, ban)
		} else if record.ReasonCode != "" || record.Reason != "" {
			record.ExplanationSource = "access-log"
			record.CorrelationType = "none"
		}
		if deniedRecordMatches(record, filter) {
			items = append(items, record)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return paginate(items, filter.Pagination), nil
}

func (s *MemoryStore) findWAFEventForAccessLogLocked(item model.AccessLog) (model.WAFEvent, bool) {
	if item.RequestID == "" {
		return model.WAFEvent{}, false
	}
	var matched model.WAFEvent
	for _, event := range s.wafEvents {
		if event.RequestID != item.RequestID {
			continue
		}
		if matched.ID == 0 || event.ID > matched.ID {
			matched = event
		}
	}
	return matched, matched.ID > 0
}

func (s *MemoryStore) findDynamicBanForAccessLogLocked(item model.AccessLog, now time.Time) (model.DynamicBan, bool) {
	var matched model.DynamicBan
	for _, ban := range s.dynamicBans {
		if ban.SiteID != item.SiteID || ban.ClientIP != item.ClientIP {
			continue
		}
		if ban.ListenerPort != item.ListenerPort || ban.Scheme != item.Scheme {
			continue
		}
		if item.CreatedAt.Before(ban.CreatedAt) || item.CreatedAt.After(ban.ExpiresAt) {
			active := dynamicBanWithStatus(ban, now)
			if active.Status != "active" {
				continue
			}
		}
		if matched.ID == 0 || ban.UpdatedAt.After(matched.UpdatedAt) || (ban.UpdatedAt.Equal(matched.UpdatedAt) && ban.ID > matched.ID) {
			matched = dynamicBanWithStatus(ban, now)
		}
	}
	return matched, matched.ID > 0
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
	s.projectDynamicBanEventLocked(item)
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

func (s *MemoryStore) ListDynamicBans(_ context.Context, filter model.DynamicBanFilter) ([]model.DynamicBan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	items := make([]model.DynamicBan, 0, len(s.dynamicBans))
	for _, item := range s.dynamicBans {
		item = dynamicBanWithStatus(item, now)
		if !dynamicBanMatches(item, filter) {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return paginate(items, filter.Pagination), nil
}

func (s *MemoryStore) ClearDynamicBan(_ context.Context, request model.DynamicBanClearRequest) (model.DynamicBanClearResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	revision := s.nextDynamicBanRevision
	s.nextDynamicBanRevision++
	status := "no-op"
	message := "dynamic ban was already cleared, expired, or not found"
	wroteClear := false
	for key, item := range s.dynamicBans {
		if item.SiteID != request.SiteID || item.ClientIP != request.ClientIP {
			continue
		}
		item = dynamicBanWithStatus(item, now)
		if item.Status == "active" {
			status = "cleared"
			message = "dynamic ban clear recorded"
		}
		item.Status = status
		item.ClearedAt = now
		item.UpdatedAt = now
		item.Revision = revision
		item.BanRemainingSec = 0
		item.Time = item.CreatedAt.Format(time.RFC3339)
		s.dynamicBans[key] = item
		clear := model.DynamicBanClearResult{
			SiteID:       item.SiteID,
			ListenerPort: item.ListenerPort,
			Scheme:       item.Scheme,
			ClientIP:     item.ClientIP,
			Status:       status,
			Revision:     revision,
			ClearedAt:    now,
			Message:      message,
		}
		s.dynamicBanClears[dynamicBanClearKey(clear)] = clear
		wroteClear = true
	}
	result := model.DynamicBanClearResult{
		SiteID:    request.SiteID,
		ClientIP:  request.ClientIP,
		Status:    status,
		Revision:  revision,
		ClearedAt: now,
		Message:   message,
	}
	if !wroteClear {
		s.dynamicBanClears[dynamicBanClearKey(result)] = result
	}
	return result, nil
}

func (s *MemoryStore) ListDynamicBanClears(_ context.Context, filter model.DynamicBanFilter) ([]model.DynamicBanClearResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.DynamicBanClearResult, 0, len(s.dynamicBanClears))
	for _, item := range s.dynamicBanClears {
		if filter.SiteID > 0 && item.SiteID != filter.SiteID {
			continue
		}
		if filter.ClientIP != "" && item.ClientIP != filter.ClientIP {
			continue
		}
		if filter.MinRevision > 0 && item.Revision <= filter.MinRevision {
			continue
		}
		if filter.ListenerPort > 0 && item.ListenerPort != filter.ListenerPort {
			continue
		}
		if filter.Scheme != "" && item.Scheme != filter.Scheme {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Revision < items[j].Revision })
	return paginate(items, filter.Pagination), nil
}

func (s *MemoryStore) GetObservabilitySummary(_ context.Context, filter model.ObservabilitySummaryFilter) (model.ObservabilitySummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := normalizeSummaryLimit(filter.Limit)
	summary := emptyObservabilitySummary()
	ipCounts := map[string]int64{}
	uriCounts := map[string]int64{}
	ruleCounts := map[string]int64{}
	typeCounts := map[string]int64{}
	attackProtectionCounts := map[string]int64{}
	accessControlCounts := map[string]int64{}
	ipAccessListCounts := map[string]int64{}
	uploadProtectionCounts := map[string]int64{}
	botProtectionCounts := map[string]int64{}
	dynamicProtectionCounts := map[string]int64{}
	trendStart, trendUntil := summaryTrendRange(filter)
	requestTrend := newSummaryTrendBuckets(trendStart)
	blockedTrend := newSummaryTrendBuckets(trendStart)
	wafMatchTrend := newSummaryTrendBuckets(trendStart)
	for _, item := range s.accessLogs {
		if summaryTimeMatches(item.CreatedAt, trendStart, trendUntil) {
			addSummaryTrendBucket(requestTrend, trendStart, item.CreatedAt, 1)
			if item.Disposition == "blocked" || item.Disposition == "rejected" {
				addSummaryTrendBucket(blockedTrend, trendStart, item.CreatedAt, 1)
			}
		}
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
		if summaryTimeMatches(item.CreatedAt, trendStart, trendUntil) {
			addSummaryTrendBucket(wafMatchTrend, trendStart, item.CreatedAt, 1)
			if item.Disposition == "blocked" || item.Disposition == "rejected" {
				addSummaryTrendBucket(blockedTrend, trendStart, item.CreatedAt, 1)
			}
		}
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
		if item.Module == "attack-protection" {
			increment(attackProtectionCounts, strings.Join([]string{item.AttackType, item.Action, item.Disposition}, "|"))
		}
		if item.Module == "access-control" {
			increment(accessControlCounts, strings.Join([]string{item.Action, item.Disposition}, "|"))
		}
		if item.Module == "ip-access-list" {
			kind := item.IPListKind
			if kind == "" {
				kind = item.Action
			}
			increment(ipAccessListCounts, strings.Join([]string{kind, item.IPListTarget, item.Action, item.Disposition}, "|"))
		}
		if item.Module == "upload-protection" {
			increment(uploadProtectionCounts, strings.Join([]string{item.Action, item.Disposition}, "|"))
		}
		if item.Module == "bot-protection" {
			botResult := item.BotResult
			if botResult == "" {
				botResult = "standard"
			}
			increment(botProtectionCounts, strings.Join([]string{item.ChallengeResult, botResult, item.Action, item.Disposition}, "|"))
		}
		if item.Module == "dynamic-protection" {
			increment(dynamicProtectionCounts, strings.Join([]string{item.Category, item.AdvancedTarget, item.Action, item.Disposition}, "|"))
		}
	}
	summary.TopIPs = topCounts(ipCounts, limit)
	summary.TopURIs = topCounts(uriCounts, limit)
	summary.TopRules = topCounts(ruleCounts, limit)
	summary.AttackTypes = topCounts(typeCounts, limit)
	summary.AccessControl = topCounts(accessControlCounts, limit)
	summary.IPAccessList = topCounts(ipAccessListCounts, limit)
	summary.AttackProtection = topCounts(attackProtectionCounts, limit)
	summary.UploadProtection = topCounts(uploadProtectionCounts, limit)
	summary.BotProtection = topCounts(botProtectionCounts, limit)
	summary.DynamicProtection = topCounts(dynamicProtectionCounts, limit)
	summary.RequestTrend = summaryTrendPoints(trendStart, requestTrend)
	summary.BlockedTrend = summaryTrendPoints(trendStart, blockedTrend)
	summary.WAFMatchTrend = summaryTrendPoints(trendStart, wafMatchTrend)
	return summary, nil
}

func (s *MemoryStore) ListIPAccessListEntries(context.Context) ([]model.IPAccessListEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.IPAccessListEntry, 0, len(s.ipAccessLists))
	for _, item := range s.ipAccessLists {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Priority == items[j].Priority {
			return items[i].ID < items[j].ID
		}
		return items[i].Priority < items[j].Priority
	})
	return items, nil
}

func (s *MemoryStore) GetIPAccessListEntry(_ context.Context, id int64) (model.IPAccessListEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.ipAccessLists[id]
	if !ok {
		return model.IPAccessListEntry{}, ErrNotFound
	}
	return item, nil
}

func (s *MemoryStore) CreateIPAccessListEntry(_ context.Context, item model.IPAccessListEntry) (model.IPAccessListEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextIPAccessListID
	item.CreatedAt = now
	item.UpdatedAt = now
	s.ipAccessLists[item.ID] = item
	s.nextIPAccessListID++
	return item, nil
}

func (s *MemoryStore) UpdateIPAccessListEntry(_ context.Context, id int64, item model.IPAccessListEntry) (model.IPAccessListEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.ipAccessLists[id]
	if !ok {
		return model.IPAccessListEntry{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	s.ipAccessLists[id] = item
	return item, nil
}

func (s *MemoryStore) DeleteIPAccessListEntry(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ipAccessLists[id]; !ok {
		return ErrNotFound
	}
	delete(s.ipAccessLists, id)
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

func (s *MemoryStore) ListUploadProtectionRules(context.Context) ([]model.UploadProtectionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.UploadProtectionRule, 0, len(s.uploadRules))
	for _, item := range s.uploadRules {
		item.Methods = cloneStrings(item.Methods)
		item.Extensions = cloneStrings(item.Extensions)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetUploadProtectionRule(_ context.Context, id int64) (model.UploadProtectionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.uploadRules[id]
	if !ok {
		return model.UploadProtectionRule{}, ErrNotFound
	}
	item.Methods = cloneStrings(item.Methods)
	item.Extensions = cloneStrings(item.Extensions)
	return item, nil
}

func (s *MemoryStore) CreateUploadProtectionRule(_ context.Context, item model.UploadProtectionRule) (model.UploadProtectionRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextUploadID
	item.CreatedAt = now
	item.UpdatedAt = now
	item.Methods = cloneStrings(item.Methods)
	item.Extensions = cloneStrings(item.Extensions)
	s.uploadRules[item.ID] = item
	s.nextUploadID++
	return item, nil
}

func (s *MemoryStore) UpdateUploadProtectionRule(_ context.Context, id int64, item model.UploadProtectionRule) (model.UploadProtectionRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.uploadRules[id]
	if !ok {
		return model.UploadProtectionRule{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	item.Methods = cloneStrings(item.Methods)
	item.Extensions = cloneStrings(item.Extensions)
	s.uploadRules[id] = item
	return item, nil
}

func (s *MemoryStore) DeleteUploadProtectionRule(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.uploadRules[id]; !ok {
		return ErrNotFound
	}
	delete(s.uploadRules, id)
	return nil
}

func (s *MemoryStore) ListBotProtectionRules(context.Context) ([]model.BotProtectionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.BotProtectionRule, 0, len(s.botRules))
	for _, item := range s.botRules {
		item.Methods = cloneStrings(item.Methods)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetBotProtectionRule(_ context.Context, id int64) (model.BotProtectionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.botRules[id]
	if !ok {
		return model.BotProtectionRule{}, ErrNotFound
	}
	item.Methods = cloneStrings(item.Methods)
	return item, nil
}

func (s *MemoryStore) CreateBotProtectionRule(_ context.Context, item model.BotProtectionRule) (model.BotProtectionRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextBotID
	item.CreatedAt = now
	item.UpdatedAt = now
	item.Methods = cloneStrings(item.Methods)
	s.botRules[item.ID] = item
	s.nextBotID++
	return item, nil
}

func (s *MemoryStore) UpdateBotProtectionRule(_ context.Context, id int64, item model.BotProtectionRule) (model.BotProtectionRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.botRules[id]
	if !ok {
		return model.BotProtectionRule{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	item.Methods = cloneStrings(item.Methods)
	s.botRules[id] = item
	return item, nil
}

func (s *MemoryStore) DeleteBotProtectionRule(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.botRules[id]; !ok {
		return ErrNotFound
	}
	delete(s.botRules, id)
	return nil
}

func (s *MemoryStore) ListDynamicProtectionRules(context.Context) ([]model.DynamicProtectionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.DynamicProtectionRule, 0, len(s.dynamicRules))
	for _, item := range s.dynamicRules {
		item.Methods = cloneStrings(item.Methods)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetDynamicProtectionRule(_ context.Context, id int64) (model.DynamicProtectionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.dynamicRules[id]
	if !ok {
		return model.DynamicProtectionRule{}, ErrNotFound
	}
	item.Methods = cloneStrings(item.Methods)
	return item, nil
}

func (s *MemoryStore) CreateDynamicProtectionRule(_ context.Context, item model.DynamicProtectionRule) (model.DynamicProtectionRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextDynamicID
	item.CreatedAt = now
	item.UpdatedAt = now
	item.Methods = cloneStrings(item.Methods)
	s.dynamicRules[item.ID] = item
	s.nextDynamicID++
	return item, nil
}

func (s *MemoryStore) UpdateDynamicProtectionRule(_ context.Context, id int64, item model.DynamicProtectionRule) (model.DynamicProtectionRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.dynamicRules[id]
	if !ok {
		return model.DynamicProtectionRule{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	item.Methods = cloneStrings(item.Methods)
	s.dynamicRules[id] = item
	return item, nil
}

func (s *MemoryStore) DeleteDynamicProtectionRule(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.dynamicRules[id]; !ok {
		return ErrNotFound
	}
	delete(s.dynamicRules, id)
	return nil
}

func (s *MemoryStore) ListProtectionRules(context.Context) ([]model.ProtectionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.ProtectionRule, 0, len(s.protectionRules))
	for _, item := range s.protectionRules {
		items = append(items, cloneProtectionRule(item))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetProtectionRule(_ context.Context, id int64) (model.ProtectionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.protectionRules[id]
	if !ok {
		return model.ProtectionRule{}, ErrNotFound
	}
	return cloneProtectionRule(item), nil
}

func (s *MemoryStore) CreateProtectionRule(_ context.Context, item model.ProtectionRule) (model.ProtectionRule, error) {
	item = protectionrules.Normalize(item)
	if err := protectionrules.Validate(item); err != nil {
		return model.ProtectionRule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextProtectionRuleID
	item.CreatedAt = now
	item.UpdatedAt = now
	item = cloneProtectionRule(item)
	s.protectionRules[item.ID] = item
	s.nextProtectionRuleID++
	return cloneProtectionRule(item), nil
}

func (s *MemoryStore) UpdateProtectionRule(_ context.Context, id int64, item model.ProtectionRule) (model.ProtectionRule, error) {
	item = protectionrules.Normalize(item)
	if err := protectionrules.Validate(item); err != nil {
		return model.ProtectionRule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.protectionRules[id]
	if !ok {
		return model.ProtectionRule{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	item = cloneProtectionRule(item)
	s.protectionRules[id] = item
	return cloneProtectionRule(item), nil
}

func (s *MemoryStore) DeleteProtectionRule(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.protectionRules[id]; !ok {
		return ErrNotFound
	}
	delete(s.protectionRules, id)
	return nil
}

func (s *MemoryStore) BackfillProtectionRules(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	created := 0
	add := func(item model.ProtectionRule) error {
		item = protectionrules.Normalize(item)
		item.ID = 0
		item.Source = protectionrules.SourceLegacy
		item.MigrationStatus = protectionrules.StatusMigrated
		if err := protectionrules.Validate(item); err != nil {
			return err
		}
		if item.LegacyRef != "" {
			for _, existing := range s.protectionRules {
				if existing.LegacyRef == item.LegacyRef {
					return nil
				}
			}
		}
		now := time.Now().UTC()
		item.ID = s.nextProtectionRuleID
		item.CreatedAt = now
		item.UpdatedAt = now
		s.protectionRules[item.ID] = cloneProtectionRule(item)
		s.nextProtectionRuleID++
		created++
		return nil
	}
	for _, item := range s.rateLimits {
		if err := add(protectionrules.FromRateLimit(item)); err != nil {
			return created, err
		}
	}
	for _, item := range s.uploadRules {
		if err := add(protectionrules.FromUpload(item)); err != nil {
			return created, err
		}
	}
	for _, item := range s.botRules {
		if err := add(protectionrules.FromBot(item)); err != nil {
			return created, err
		}
	}
	for _, item := range s.dynamicRules {
		if err := add(protectionrules.FromDynamic(item)); err != nil {
			return created, err
		}
	}
	for _, raw := range s.rules {
		rule := attackmeta.NormalizeRule(raw)
		if rule.Module != attackmeta.Module || rule.Category != attackmeta.Category {
			continue
		}
		if err := add(protectionrules.FromAttackRule(rule)); err != nil {
			return created, err
		}
	}
	return created, nil
}

func (s *MemoryStore) ListRuleCatalogSources(context.Context) ([]model.RuleCatalogSource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleCatalogSource, 0, len(s.catalogSources))
	for _, item := range s.catalogSources {
		item.PackageCount = s.catalogPackageCountLocked(item.ID)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetRuleCatalogSource(_ context.Context, id int64) (model.RuleCatalogSource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.catalogSources[id]
	if !ok {
		return model.RuleCatalogSource{}, ErrNotFound
	}
	item.PackageCount = s.catalogPackageCountLocked(id)
	return item, nil
}

func (s *MemoryStore) CreateRuleCatalogSource(_ context.Context, item model.RuleCatalogSource) (model.RuleCatalogSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextCatalogID
	item.CreatedAt = now
	item.UpdatedAt = now
	if item.Status == "" {
		item.Status = "never-synced"
	}
	s.catalogSources[item.ID] = item
	s.nextCatalogID++
	return item, nil
}

func (s *MemoryStore) UpdateRuleCatalogSource(_ context.Context, id int64, item model.RuleCatalogSource) (model.RuleCatalogSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.catalogSources[id]
	if !ok {
		return model.RuleCatalogSource{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	s.catalogSources[id] = item
	return item, nil
}

func (s *MemoryStore) DeleteRuleCatalogSource(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.catalogSources[id]; !ok {
		return ErrNotFound
	}
	delete(s.catalogSources, id)
	for packageID, item := range s.catalogPackages {
		if item.CatalogID == id {
			delete(s.catalogPackages, packageID)
		}
	}
	return nil
}

func (s *MemoryStore) ListRuleCatalogPackages(_ context.Context, catalogID int64) ([]model.RuleCatalogPackage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleCatalogPackage, 0, len(s.catalogPackages))
	for _, item := range s.catalogPackages {
		if catalogID > 0 && item.CatalogID != catalogID {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CatalogID == items[j].CatalogID {
			return items[i].PackageID < items[j].PackageID
		}
		return items[i].CatalogID < items[j].CatalogID
	})
	return items, nil
}

func (s *MemoryStore) GetRuleCatalogPackage(_ context.Context, catalogID int64, packageID string) (model.RuleCatalogPackage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.catalogPackages {
		if item.CatalogID == catalogID && item.PackageID == packageID {
			return item, nil
		}
	}
	return model.RuleCatalogPackage{}, ErrNotFound
}

func (s *MemoryStore) ReplaceRuleCatalogPackages(_ context.Context, catalogID int64, items []model.RuleCatalogPackage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.catalogSources[catalogID]; !ok {
		return ErrNotFound
	}
	for id, item := range s.catalogPackages {
		if item.CatalogID == catalogID {
			delete(s.catalogPackages, id)
		}
	}
	now := time.Now().UTC()
	for _, item := range items {
		item.ID = s.nextCatalogPackageID
		item.CatalogID = catalogID
		item.CreatedAt = now
		item.UpdatedAt = now
		if item.LastSyncedAt.IsZero() {
			item.LastSyncedAt = now
		}
		s.catalogPackages[item.ID] = item
		s.nextCatalogPackageID++
	}
	source := s.catalogSources[catalogID]
	source.Status = "synced"
	source.LastError = ""
	source.LastSyncAt = now
	source.UpdatedAt = now
	s.catalogSources[catalogID] = source
	return nil
}

func (s *MemoryStore) ListRuleTrustKeys(context.Context) ([]model.RuleTrustKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleTrustKey, 0, len(s.trustKeys))
	for _, item := range s.trustKeys {
		item.PublicKey = ""
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetRuleTrustKey(_ context.Context, keyID string) (model.RuleTrustKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.trustKeys {
		if item.KeyID == keyID {
			return item, nil
		}
	}
	return model.RuleTrustKey{}, ErrNotFound
}

func (s *MemoryStore) CreateRuleTrustKey(_ context.Context, item model.RuleTrustKey) (model.RuleTrustKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextTrustKeyID
	item.CreatedAt = now
	item.UpdatedAt = now
	s.trustKeys[item.ID] = item
	s.nextTrustKeyID++
	item.PublicKey = ""
	return item, nil
}

func (s *MemoryStore) UpdateRuleTrustKey(_ context.Context, id int64, item model.RuleTrustKey) (model.RuleTrustKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.trustKeys[id]
	if !ok {
		return model.RuleTrustKey{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	if item.PublicKey == "" {
		item.PublicKey = existing.PublicKey
	}
	s.trustKeys[id] = item
	item.PublicKey = ""
	return item, nil
}

func (s *MemoryStore) ListRuleProviderAdapters(context.Context) ([]model.RuleProviderAdapter, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleProviderAdapter, 0, len(s.providers))
	for _, item := range s.providers {
		item.PackageCount = s.providerPackageCountLocked(item.ID)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetRuleProviderAdapter(_ context.Context, id int64) (model.RuleProviderAdapter, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.providers[id]
	if !ok {
		return model.RuleProviderAdapter{}, ErrNotFound
	}
	item.PackageCount = s.providerPackageCountLocked(id)
	return item, nil
}

func (s *MemoryStore) CreateRuleProviderAdapter(_ context.Context, item model.RuleProviderAdapter, secret model.RuleCommunityAccountSecret) (model.RuleProviderAdapter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextProviderID
	item.CreatedAt = now
	item.UpdatedAt = now
	item.Credential = redactCredential(item.Credential, secret.Secret, now)
	s.providers[item.ID] = item
	if secret.Secret != "" {
		s.providerSecrets[item.ID] = secret.Secret
	}
	s.nextProviderID++
	return item, nil
}

func (s *MemoryStore) UpdateRuleProviderAdapter(_ context.Context, id int64, item model.RuleProviderAdapter, secret model.RuleCommunityAccountSecret) (model.RuleProviderAdapter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.providers[id]
	if !ok {
		return model.RuleProviderAdapter{}, ErrNotFound
	}
	now := time.Now().UTC()
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = now
	item.LastSyncAt = existing.LastSyncAt
	item.LastFailedSyncAt = existing.LastFailedSyncAt
	item.LastError = existing.LastError
	item.AttemptCount = existing.AttemptCount
	item.NextRetryAt = existing.NextRetryAt
	item.RetryExhausted = existing.RetryExhausted
	if secret.Secret == "" {
		item.Credential = existing.Credential
	} else {
		item.Credential = redactCredential(item.Credential, secret.Secret, now)
		s.providerSecrets[id] = secret.Secret
	}
	s.providers[id] = item
	item.PackageCount = s.providerPackageCountLocked(id)
	return item, nil
}

func (s *MemoryStore) DeleteRuleProviderAdapter(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.providers[id]; !ok {
		return ErrNotFound
	}
	delete(s.providers, id)
	delete(s.providerSecrets, id)
	for packageID, item := range s.providerPackages {
		if item.ProviderID == id {
			delete(s.providerPackages, packageID)
		}
	}
	return nil
}

func (s *MemoryStore) UpdateRuleProviderSyncState(_ context.Context, id int64, item model.RuleProviderAdapter, packages []model.RuleProviderPackage) (model.RuleProviderAdapter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.providers[id]
	if !ok {
		return model.RuleProviderAdapter{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	item.Credential = existing.Credential
	s.providers[id] = item
	if packages != nil {
		for packageID, candidate := range s.providerPackages {
			if candidate.ProviderID == id {
				delete(s.providerPackages, packageID)
			}
		}
		for _, candidate := range packages {
			candidate.ID = s.nextProviderPackageID
			candidate.ProviderID = id
			candidate.ProviderName = item.Name
			candidate.ProviderType = item.ProviderType
			candidate.CreatedAt = item.UpdatedAt
			candidate.UpdatedAt = item.UpdatedAt
			if candidate.LastSyncedAt.IsZero() {
				candidate.LastSyncedAt = item.UpdatedAt
			}
			s.providerPackages[candidate.ID] = candidate
			s.nextProviderPackageID++
		}
	}
	item.PackageCount = s.providerPackageCountLocked(id)
	s.providers[id] = item
	return item, nil
}

func (s *MemoryStore) ListRuleProviderPackages(_ context.Context, providerID int64) ([]model.RuleProviderPackage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleProviderPackage, 0, len(s.providerPackages))
	for _, item := range s.providerPackages {
		if providerID > 0 && item.ProviderID != providerID {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ProviderID == items[j].ProviderID {
			return items[i].PackageID < items[j].PackageID
		}
		return items[i].ProviderID < items[j].ProviderID
	})
	return items, nil
}

func (s *MemoryStore) GetRuleProviderPackage(_ context.Context, providerID int64, packageID string) (model.RuleProviderPackage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.providerPackages {
		if item.ProviderID == providerID && (item.PackageID == packageID || item.ProviderPackageRef == packageID) {
			return item, nil
		}
	}
	return model.RuleProviderPackage{}, ErrNotFound
}

func (s *MemoryStore) catalogPackageCountLocked(catalogID int64) int {
	count := 0
	for _, item := range s.catalogPackages {
		if item.CatalogID == catalogID {
			count++
		}
	}
	return count
}

func (s *MemoryStore) providerPackageCountLocked(providerID int64) int {
	count := 0
	for _, item := range s.providerPackages {
		if item.ProviderID == providerID {
			count++
		}
	}
	return count
}

func (s *MemoryStore) ListRuleCommunityAccountSources(context.Context) ([]model.RuleCommunityAccountSource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleCommunityAccountSource, 0, len(s.accountSources))
	for _, item := range s.accountSources {
		item.RecommendationCount = s.recommendationCountLocked(item.ID)
		item = s.attachProviderStateLocked(item)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetRuleCommunityAccountSource(_ context.Context, id int64) (model.RuleCommunityAccountSource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.accountSources[id]
	if !ok {
		return model.RuleCommunityAccountSource{}, ErrNotFound
	}
	item.RecommendationCount = s.recommendationCountLocked(id)
	return s.attachProviderStateLocked(item), nil
}

func (s *MemoryStore) CreateRuleCommunityAccountSource(_ context.Context, item model.RuleCommunityAccountSource, secret model.RuleCommunityAccountSecret) (model.RuleCommunityAccountSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextAccountSourceID
	item.CreatedAt = now
	item.UpdatedAt = now
	item.Credential = redactCredential(item.Credential, secret.Secret, now)
	s.accountSources[item.ID] = item
	if secret.Secret != "" {
		s.accountSecrets[item.ID] = secret.Secret
	}
	s.nextAccountSourceID++
	return item, nil
}

func (s *MemoryStore) UpdateRuleCommunityAccountSource(_ context.Context, id int64, item model.RuleCommunityAccountSource, secret model.RuleCommunityAccountSecret) (model.RuleCommunityAccountSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.accountSources[id]
	if !ok {
		return model.RuleCommunityAccountSource{}, ErrNotFound
	}
	now := time.Now().UTC()
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = now
	if secret.Secret == "" {
		item.Credential = existing.Credential
	} else {
		item.Credential = redactCredential(item.Credential, secret.Secret, now)
		s.accountSecrets[id] = secret.Secret
	}
	item.LastSyncAt = existing.LastSyncAt
	item.LastError = existing.LastError
	s.accountSources[id] = item
	return item, nil
}

func (s *MemoryStore) DeleteRuleCommunityAccountSource(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accountSources[id]; !ok {
		return ErrNotFound
	}
	delete(s.accountSources, id)
	delete(s.accountSecrets, id)
	return nil
}

func (s *MemoryStore) RefreshRuleCommunityAccountSource(_ context.Context, id int64, item model.RuleCommunityAccountSource, queue []model.RuleReviewQueueItem) (model.RuleCommunityAccountSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.accountSources[id]
	if !ok {
		return model.RuleCommunityAccountSource{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	item.Credential = existing.Credential
	s.accountSources[id] = item
	for _, queueItem := range queue {
		queueItem.ID = s.nextReviewQueueID
		queueItem.CreatedAt = item.UpdatedAt
		queueItem.UpdatedAt = item.UpdatedAt
		s.reviewQueue[queueItem.ID] = queueItem
		s.nextReviewQueueID++
	}
	item.RecommendationCount = s.recommendationCountLocked(id)
	return item, nil
}

func (s *MemoryStore) ListRuleContributionTargets(context.Context) ([]model.RuleContributionTarget, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleContributionTarget, 0, len(s.contributionTargets))
	for _, item := range s.contributionTargets {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetRuleContributionTarget(_ context.Context, id int64) (model.RuleContributionTarget, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.contributionTargets[id]
	if !ok {
		return model.RuleContributionTarget{}, ErrNotFound
	}
	return item, nil
}

func (s *MemoryStore) CreateRuleContributionTarget(_ context.Context, item model.RuleContributionTarget, secret model.RuleCommunityAccountSecret) (model.RuleContributionTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextContributionID
	item.CreatedAt = now
	item.UpdatedAt = now
	item.Credential = redactCredential(item.Credential, secret.Secret, now)
	s.contributionTargets[item.ID] = item
	if secret.Secret != "" {
		s.contributionSecrets[item.ID] = secret.Secret
	}
	s.nextContributionID++
	return item, nil
}

func (s *MemoryStore) CreateRuleContributionPushAttempt(_ context.Context, item model.RuleContributionPushAttempt) (model.RuleContributionPushAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item.ID = s.nextPushAttemptID
	item.CreatedAt = time.Now().UTC()
	s.pushAttempts[item.ID] = item
	target := s.contributionTargets[item.TargetID]
	target.LastPushAt = item.CreatedAt
	target.LastError = item.Error
	target.Status = item.Status
	target.UpdatedAt = item.CreatedAt
	s.contributionTargets[item.TargetID] = target
	s.nextPushAttemptID++
	return item, nil
}

func (s *MemoryStore) ListRuleContributionPushAttempts(context.Context) ([]model.RuleContributionPushAttempt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleContributionPushAttempt, 0, len(s.pushAttempts))
	for _, item := range s.pushAttempts {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return items, nil
}

func (s *MemoryStore) ListRuleReviewQueueItems(context.Context) ([]model.RuleReviewQueueItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleReviewQueueItem, 0, len(s.reviewQueue))
	for _, item := range s.reviewQueue {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetRuleReviewQueueItem(_ context.Context, id int64) (model.RuleReviewQueueItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.reviewQueue[id]
	if !ok {
		return model.RuleReviewQueueItem{}, ErrNotFound
	}
	return item, nil
}

func (s *MemoryStore) CreateRuleReviewQueueItem(_ context.Context, item model.RuleReviewQueueItem) (model.RuleReviewQueueItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextReviewQueueID
	item.CreatedAt = now
	item.UpdatedAt = now
	s.reviewQueue[item.ID] = item
	s.nextReviewQueueID++
	return item, nil
}

func (s *MemoryStore) UpdateRuleReviewQueueItem(_ context.Context, id int64, item model.RuleReviewQueueItem) (model.RuleReviewQueueItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.reviewQueue[id]
	if !ok {
		return model.RuleReviewQueueItem{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	s.reviewQueue[id] = item
	return item, nil
}

func (s *MemoryStore) ListRuleFeedback(context.Context) ([]model.RuleFeedback, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleFeedback, 0, len(s.feedback))
	for _, item := range s.feedback {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) CreateRuleFeedback(_ context.Context, item model.RuleFeedback) (model.RuleFeedback, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextFeedbackID
	item.CreatedAt = now
	item.UpdatedAt = now
	s.feedback[item.ID] = item
	s.nextFeedbackID++
	return item, nil
}

func (s *MemoryStore) ListRuleFeedbackSuggestions(context.Context) ([]model.RuleFeedbackSuggestion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.RuleFeedbackSuggestion, 0, len(s.feedbackSuggestions))
	for _, item := range s.feedbackSuggestions {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (s *MemoryStore) GetRuleFeedbackSuggestion(_ context.Context, id int64) (model.RuleFeedbackSuggestion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.feedbackSuggestions[id]
	if !ok {
		return model.RuleFeedbackSuggestion{}, ErrNotFound
	}
	return item, nil
}

func (s *MemoryStore) CreateRuleFeedbackSuggestion(_ context.Context, item model.RuleFeedbackSuggestion) (model.RuleFeedbackSuggestion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	item.ID = s.nextSuggestionID
	item.CreatedAt = now
	item.UpdatedAt = now
	s.feedbackSuggestions[item.ID] = item
	s.nextSuggestionID++
	return item, nil
}

func (s *MemoryStore) UpdateRuleFeedbackSuggestion(_ context.Context, id int64, item model.RuleFeedbackSuggestion) (model.RuleFeedbackSuggestion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.feedbackSuggestions[id]
	if !ok {
		return model.RuleFeedbackSuggestion{}, ErrNotFound
	}
	item.ID = id
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now().UTC()
	s.feedbackSuggestions[id] = item
	return item, nil
}

func (s *MemoryStore) recommendationCountLocked(sourceID int64) int {
	count := 0
	needle := "account:" + strconv.FormatInt(sourceID, 10)
	for _, item := range s.reviewQueue {
		if item.SourceIdentity == needle && item.State == "queued" {
			count++
		}
	}
	return count
}

func (s *MemoryStore) attachProviderStateLocked(item model.RuleCommunityAccountSource) model.RuleCommunityAccountSource {
	if item.ProviderAdapterID <= 0 {
		return item
	}
	provider, ok := s.providers[item.ProviderAdapterID]
	if !ok {
		item.ProviderHealth = "missing"
		item.ProviderRetryState = "unavailable"
		return item
	}
	item.ProviderAdapterName = provider.Name
	item.ProviderHealth = provider.HealthStatus
	if provider.RetryExhausted {
		item.ProviderRetryState = "exhausted"
	} else if provider.AttemptCount > 0 {
		item.ProviderRetryState = "retrying"
	} else {
		item.ProviderRetryState = "ready"
	}
	return item
}

func redactCredential(meta model.RuleAccountCredential, secret string, now time.Time) model.RuleAccountCredential {
	if meta.Alias == "" {
		meta.Alias = "default"
	}
	if secret != "" {
		meta.LastFour = lastFour(secret)
		meta.Fingerprint = "sha256:" + strconv.FormatInt(int64(len(secret)), 10) + ":" + lastFour(secret)
		meta.LastValidatedAt = now
		meta.Status = "configured"
	}
	if meta.Status == "" {
		meta.Status = "not-configured"
	}
	return meta
}

func lastFour(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 4 {
		return value
	}
	return value[len(value)-4:]
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
	if filter.ListenerPort > 0 && item.ListenerPort != filter.ListenerPort {
		return false
	}
	if filter.Scheme != "" && item.Scheme != filter.Scheme {
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
	if filter.ReasonCode != "" && item.ReasonCode != filter.ReasonCode {
		return false
	}
	return summaryTimeMatches(item.CreatedAt, filter.Since, filter.Until)
}

func wafEventMatches(item model.WAFEvent, filter model.WAFEventFilter) bool {
	if filter.SiteID > 0 && item.SiteID != filter.SiteID {
		return false
	}
	if filter.ListenerPort > 0 && item.ListenerPort != filter.ListenerPort {
		return false
	}
	if filter.Scheme != "" && item.Scheme != filter.Scheme {
		return false
	}
	if filter.Host != "" && item.Host != filter.Host {
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
	if filter.Module != "" && item.Module != filter.Module {
		return false
	}
	if filter.AttackType != "" && item.AttackType != filter.AttackType {
		return false
	}
	if filter.AdvancedTarget != "" && item.AdvancedTarget != filter.AdvancedTarget && item.Target != filter.AdvancedTarget {
		return false
	}
	if filter.ChallengeResult != "" && item.ChallengeResult != filter.ChallengeResult {
		return false
	}
	if filter.BotResult != "" && item.BotResult != filter.BotResult {
		return false
	}
	if filter.DynamicResult != "" && item.AdvancedTarget != filter.DynamicResult {
		return false
	}
	if filter.MinScore > 0 && item.Score < filter.MinScore {
		return false
	}
	return summaryTimeMatches(item.CreatedAt, filter.Since, filter.Until)
}

func (s *MemoryStore) projectDynamicBanEventLocked(item model.WAFEvent) {
	if item.EventType != "dynamic-ban" || item.SiteID <= 0 || item.ClientIP == "" {
		return
	}
	duration := item.BanDurationSec
	if duration <= 0 {
		duration = item.BanRemainingSec
	}
	if duration <= 0 {
		return
	}
	now := item.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	key := dynamicBanKey(item.SiteID, item.ListenerPort, item.Scheme, item.ClientIP)
	existing, ok := s.dynamicBans[key]
	if !ok {
		existing.ID = s.nextDynamicBanID
		s.nextDynamicBanID++
		existing.CreatedAt = now
	}
	existing.SiteID = item.SiteID
	existing.ListenerPort = item.ListenerPort
	existing.Scheme = item.Scheme
	existing.ClientIP = item.ClientIP
	existing.BanReason = item.BanReason
	existing.Source = dynamicBanSource(item)
	existing.SourceEventID = item.ID
	existing.BanDurationSec = duration
	existing.BanRemainingSec = duration
	if item.BanRemainingSec > 0 {
		existing.BanRemainingSec = item.BanRemainingSec
	}
	existing.Status = "active"
	existing.ExpiresAt = now.Add(time.Duration(existing.BanRemainingSec) * time.Second)
	existing.ClearedAt = time.Time{}
	existing.UpdatedAt = now
	existing.Time = existing.CreatedAt.Format(time.RFC3339)
	s.dynamicBans[key] = existing
}

func dynamicBanKey(siteID int64, listenerPort int, scheme string, clientIP string) string {
	return strconv.FormatInt(siteID, 10) + "|" + strconv.Itoa(listenerPort) + "|" + scheme + "|" + clientIP
}

func dynamicBanClearKey(item model.DynamicBanClearResult) string {
	return strconv.FormatInt(item.Revision, 10) + "|" + strconv.FormatInt(item.SiteID, 10) + "|" + strconv.Itoa(item.ListenerPort) + "|" + item.Scheme + "|" + item.ClientIP
}

func dynamicBanSource(item model.WAFEvent) string {
	if item.Module != "" && item.RuleName != "" {
		return item.Module + ":" + item.RuleName
	}
	if item.Module != "" {
		return item.Module
	}
	if item.BanReason != "" {
		return item.BanReason
	}
	return item.EventType
}

func dynamicBanWithStatus(item model.DynamicBan, now time.Time) model.DynamicBan {
	if item.Status == "active" {
		remaining := int(time.Until(item.ExpiresAt).Seconds())
		if !now.IsZero() {
			remaining = int(item.ExpiresAt.Sub(now).Seconds())
		}
		if remaining <= 0 {
			item.Status = "expired"
			item.BanRemainingSec = 0
		} else {
			item.BanRemainingSec = remaining
		}
	}
	item.Time = item.CreatedAt.Format(time.RFC3339)
	return item
}

func dynamicBanMatches(item model.DynamicBan, filter model.DynamicBanFilter) bool {
	if filter.SiteID > 0 && item.SiteID != filter.SiteID {
		return false
	}
	if filter.ClientIP != "" && item.ClientIP != filter.ClientIP {
		return false
	}
	if filter.ListenerPort > 0 && item.ListenerPort != filter.ListenerPort {
		return false
	}
	if filter.Scheme != "" && item.Scheme != filter.Scheme {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.MinRevision > 0 && item.Revision <= filter.MinRevision {
		return false
	}
	return true
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
		_, applicationExists := s.applications[id]
		_, legacySiteExists := s.sites[id]
		if !applicationExists && !legacySiteExists {
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

func (s *MemoryStore) certificateExistsLocked(id int64) bool {
	_, ok := s.certificates[id]
	return ok
}

func (s *MemoryStore) certificateInUseLocked(id int64) bool {
	for _, app := range s.applications {
		for _, listener := range app.Listeners {
			if listener.Enabled && listener.CertificateID == id {
				return true
			}
		}
	}
	return false
}

func (s *MemoryStore) assignApplicationChildIDsLocked(app *model.Application) {
	for i := range app.Hosts {
		app.Hosts[i].ApplicationID = app.ID
		if app.Hosts[i].ID == 0 {
			app.Hosts[i].ID = s.nextApplicationHostID
			s.nextApplicationHostID++
		}
	}
	for i := range app.Listeners {
		app.Listeners[i].ApplicationID = app.ID
		if app.Listeners[i].ID == 0 {
			app.Listeners[i].ID = s.nextApplicationListenerID
			s.nextApplicationListenerID++
		}
	}
	for i := range app.Upstreams {
		app.Upstreams[i].ApplicationID = app.ID
		if app.Upstreams[i].ID == 0 {
			app.Upstreams[i].ID = s.nextApplicationUpstreamID
			s.nextApplicationUpstreamID++
		}
	}
}

func cloneApplication(item model.Application) model.Application {
	item.Hosts = append([]model.ApplicationHost(nil), item.Hosts...)
	item.Listeners = append([]model.ApplicationListener(nil), item.Listeners...)
	item.Upstreams = append([]model.ApplicationUpstream(nil), item.Upstreams...)
	return item
}

func cloneCertificate(item model.Certificate) model.Certificate {
	item.Domains = cloneStrings(item.Domains)
	return item
}

func cloneIDs(ids []int64) []int64 {
	if ids == nil {
		return []int64{}
	}
	out := make([]int64, len(ids))
	copy(out, ids)
	return out
}

func cloneStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func cloneProtectionRule(item model.ProtectionRule) model.ProtectionRule {
	item.Match.Methods = cloneStrings(item.Match.Methods)
	if item.Upload != nil {
		upload := *item.Upload
		upload.Extensions = cloneStrings(upload.Extensions)
		item.Upload = &upload
	}
	if item.Challenge != nil {
		challenge := *item.Challenge
		item.Challenge = &challenge
	}
	if item.Dynamic != nil {
		dynamic := *item.Dynamic
		item.Dynamic = &dynamic
	}
	return item
}
