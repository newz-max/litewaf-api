package store

import (
	"context"
	"testing"

	"litewaf-api/internal/model"
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
