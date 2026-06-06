package store

import (
	"context"
	"testing"
	"time"

	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
)

func TestMemoryStoreSiteCreateAndList(t *testing.T) {
	ctx := context.Background()
	dataStore := NewMemoryStore()

	sites, err := dataStore.ListSites(ctx)
	if err != nil {
		t.Fatalf("list empty sites: %v", err)
	}
	if len(sites) != 0 {
		t.Fatalf("expected empty sites, got %d", len(sites))
	}

	created, err := dataStore.CreateSite(ctx, model.Site{
		Name:     "Example",
		Host:     "example.test",
		Upstream: "http://upstream:8080",
		Mode:     "protect",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected site id")
	}

	loaded, err := dataStore.GetSite(ctx, created.ID)
	if err != nil {
		t.Fatalf("get site: %v", err)
	}
	if loaded.Host != "example.test" {
		t.Fatalf("unexpected host %q", loaded.Host)
	}
}

func TestMemoryStoreApplicationAndCertificateCRUD(t *testing.T) {
	ctx := context.Background()
	dataStore := NewMemoryStore()

	cert, err := dataStore.CreateCertificate(ctx, model.Certificate{
		Name:        "App cert",
		Domains:     []string{"app.example.test"},
		CertPEM:     "cert",
		KeyPEM:      "key",
		NotBefore:   time.Now().UTC().Add(-time.Hour),
		NotAfter:    time.Now().UTC().Add(time.Hour),
		Fingerprint: "abc123",
	})
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	created, err := dataStore.CreateApplication(ctx, model.Application{
		Name:    "Example App",
		Mode:    model.ApplicationModeProtect,
		Enabled: true,
		Hosts: []model.ApplicationHost{
			{Host: "app.example.test", IsPrimary: true},
		},
		Listeners: []model.ApplicationListener{
			{Port: 80, Protocol: model.ListenerProtocolHTTP, Enabled: true},
			{Port: 443, Protocol: model.ListenerProtocolHTTPS, CertificateID: cert.ID, Enabled: true},
		},
		Upstreams: []model.ApplicationUpstream{
			{Name: "primary", URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	if created.ID == 0 || len(created.Hosts) != 1 || len(created.Listeners) != 2 || len(created.Upstreams) != 1 {
		t.Fatalf("unexpected created application: %+v", created)
	}

	inUse, err := dataStore.CertificateInUse(ctx, cert.ID)
	if err != nil {
		t.Fatalf("certificate in use: %v", err)
	}
	if !inUse {
		t.Fatal("expected certificate to be in use")
	}
	if err := dataStore.DeleteCertificate(ctx, cert.ID); err == nil {
		t.Fatal("expected in-use certificate delete to fail")
	}

	loaded, err := dataStore.GetApplication(ctx, created.ID)
	if err != nil {
		t.Fatalf("get application: %v", err)
	}
	if loaded.Hosts[0].Host != "app.example.test" || loaded.Listeners[1].CertificateID != cert.ID {
		t.Fatalf("unexpected loaded application: %+v", loaded)
	}
}

func TestMemoryStoreApplicationValidation(t *testing.T) {
	ctx := context.Background()
	dataStore := NewMemoryStore()
	_, err := dataStore.CreateApplication(ctx, model.Application{
		Name:    "Bad HTTPS",
		Mode:    model.ApplicationModeProtect,
		Enabled: true,
		Hosts:   []model.ApplicationHost{{Host: "bad.example.test"}},
		Listeners: []model.ApplicationListener{
			{Port: 443, Protocol: model.ListenerProtocolHTTPS, Enabled: true},
		},
		Upstreams: []model.ApplicationUpstream{{URL: "http://127.0.0.1:9000", Enabled: true}},
	})
	if err == nil {
		t.Fatal("expected https listener without certificate to fail")
	}
}

func TestMemoryStorePolicyRejectsMissingBindings(t *testing.T) {
	ctx := context.Background()
	dataStore := NewMemoryStore()

	_, err := dataStore.CreatePolicy(ctx, model.Policy{
		Name:          "Invalid",
		RiskThreshold: 100,
		DefaultAction: "block",
		Enabled:       true,
		SiteIDs:       []int64{404},
		RuleIDs:       []int64{1},
	})
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStoreProtectionRuleValidationAndBackfill(t *testing.T) {
	ctx := context.Background()
	dataStore := NewMemoryStore()

	_, err := dataStore.CreateProtectionRule(ctx, model.ProtectionRule{
		Name:     "bad",
		Module:   "cc-protection",
		Category: "upload",
		Enabled:  true,
		Match: model.ProtectionRuleMatch{
			Path:      "/api",
			PathMatch: "prefix",
		},
		Limit: model.ProtectionRuleLimit{
			Counter:   "client_ip",
			Threshold: 10,
			WindowSec: 60,
		},
		Action: model.ProtectionRuleAction{Type: "block"},
	})
	if err == nil {
		t.Fatal("expected invalid module/category mapping to fail")
	}

	legacy, err := dataStore.CreateRateLimitRule(ctx, model.RateLimitRule{
		Name:       "Login limit",
		Scope:      "ip",
		PathMatch:  "exact",
		MatchValue: "/login",
		Threshold:  10,
		WindowSec:  60,
		Action:     "block",
		CCAction:   "ban",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("create legacy rate limit: %v", err)
	}
	created, err := dataStore.BackfillProtectionRules(ctx)
	if err != nil {
		t.Fatalf("backfill protection rules: %v", err)
	}
	if created < 1 {
		t.Fatalf("expected backfilled rules, got %d", created)
	}
	created, err = dataStore.BackfillProtectionRules(ctx)
	if err != nil {
		t.Fatalf("rerun backfill: %v", err)
	}
	if created != 0 {
		t.Fatalf("expected idempotent backfill, got %d new rows", created)
	}
	rules, err := dataStore.ListProtectionRules(ctx)
	if err != nil {
		t.Fatalf("list protection rules: %v", err)
	}
	var rule model.ProtectionRule
	for _, item := range rules {
		if item.LegacyRef == protectionrules.LegacyRef("rate_limits", legacy.ID) {
			rule = item
			break
		}
	}
	if rule.LegacyRef != protectionrules.LegacyRef("rate_limits", legacy.ID) || rule.MigrationStatus != protectionrules.StatusMigrated {
		t.Fatalf("unexpected migration metadata: %+v", rule)
	}
	if rule.Module != protectionrules.ModuleCC || rule.Limit.Counter != "client_ip" || rule.Action.Type != "ban" {
		t.Fatalf("unexpected backfilled rule: %+v", rule)
	}
}

func TestMemoryStoreDynamicBanLifecycle(t *testing.T) {
	ctx := context.Background()
	dataStore := NewMemoryStore()
	now := time.Now().UTC()

	if _, err := dataStore.CreateWAFEvent(ctx, model.WAFEvent{
		RequestID:       "ban-site-1",
		SiteID:          1,
		EventType:       "dynamic-ban",
		Action:          "block",
		Disposition:     "blocked",
		ClientIP:        "192.0.2.10",
		BanReason:       "cc-protection:1",
		BanDurationSec:  300,
		BanRemainingSec: 300,
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("create ban event: %v", err)
	}
	if _, err := dataStore.CreateWAFEvent(ctx, model.WAFEvent{
		RequestID:       "ban-site-2",
		SiteID:          2,
		EventType:       "dynamic-ban",
		Action:          "block",
		Disposition:     "blocked",
		ClientIP:        "192.0.2.10",
		BanReason:       "cc-protection:2",
		BanDurationSec:  300,
		BanRemainingSec: 300,
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("create second site ban event: %v", err)
	}
	if _, err := dataStore.CreateWAFEvent(ctx, model.WAFEvent{
		RequestID:      "expired",
		SiteID:         1,
		EventType:      "dynamic-ban",
		Action:         "block",
		Disposition:    "blocked",
		ClientIP:       "192.0.2.20",
		BanReason:      "score-threshold",
		BanDurationSec: 1,
		CreatedAt:      now.Add(-2 * time.Minute),
	}); err != nil {
		t.Fatalf("create expired ban event: %v", err)
	}

	active, err := dataStore.ListDynamicBans(ctx, model.DynamicBanFilter{SiteID: 1, Status: "active"})
	if err != nil {
		t.Fatalf("list active bans: %v", err)
	}
	if len(active) != 1 || active[0].ClientIP != "192.0.2.10" {
		t.Fatalf("unexpected active bans: %+v", active)
	}

	cleared, err := dataStore.ClearDynamicBan(ctx, model.DynamicBanClearRequest{SiteID: 1, ClientIP: "192.0.2.10", Actor: "admin"})
	if err != nil {
		t.Fatalf("clear ban: %v", err)
	}
	if cleared.Status != "cleared" || cleared.Revision == 0 {
		t.Fatalf("unexpected clear result: %+v", cleared)
	}
	repeated, err := dataStore.ClearDynamicBan(ctx, model.DynamicBanClearRequest{SiteID: 1, ClientIP: "192.0.2.10", Actor: "admin"})
	if err != nil {
		t.Fatalf("repeat clear ban: %v", err)
	}
	if repeated.Status != "no-op" || repeated.Revision <= cleared.Revision {
		t.Fatalf("unexpected repeated clear result: %+v", repeated)
	}

	active, err = dataStore.ListDynamicBans(ctx, model.DynamicBanFilter{SiteID: 1, Status: "active"})
	if err != nil {
		t.Fatalf("list active after clear: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active bans for site 1, got %+v", active)
	}
	active, err = dataStore.ListDynamicBans(ctx, model.DynamicBanFilter{SiteID: 2, Status: "active"})
	if err != nil {
		t.Fatalf("list site 2 active: %v", err)
	}
	if len(active) != 1 || active[0].ClientIP != "192.0.2.10" {
		t.Fatalf("expected unrelated site ban to remain active, got %+v", active)
	}

	clears, err := dataStore.ListDynamicBanClears(ctx, model.DynamicBanFilter{MinRevision: cleared.Revision})
	if err != nil {
		t.Fatalf("list clear feed: %v", err)
	}
	if len(clears) != 1 || clears[0].Status != "no-op" {
		t.Fatalf("unexpected clear feed: %+v", clears)
	}
}
