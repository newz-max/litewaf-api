package geoip

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolverMatchesCIDRAndIgnoresReservedIPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.csv")
	data := "cidr,country_code,country,region,city,district,longitude,latitude,source,version\n" +
		"8.8.8.0/24,CN,中国,北京,北京,朝阳区,116.4,39.9,test-db,2026\n" +
		"1.1.1.0/24,SG,新加坡,,,,103.8,1.3,test-db,2026\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write geoip db: %v", err)
	}
	resolver := NewResolver(Options{DatabasePath: path, CacheSize: 2})

	result := resolver.Resolve("8.8.8.8")
	if !result.Resolved || result.Country != "中国" || result.Region != "北京" || result.City != "北京" || result.District != "朝阳区" || result.Source != "test-db" {
		t.Fatalf("unexpected resolved result: %+v", result)
	}
	if result := resolver.Resolve("198.51.100.10"); result.Resolved || result.UnresolvedReason != ReasonReservedIP {
		t.Fatalf("expected reserved documentation IP to remain unresolved, got %+v", result)
	}
	if result := resolver.Resolve("9.9.9.9"); result.Resolved || result.UnresolvedReason != ReasonNoMatch {
		t.Fatalf("expected no-match result, got %+v", result)
	}
}

func TestResolverMissingDatabaseDiagnostics(t *testing.T) {
	resolver := NewResolver(Options{})
	result := resolver.Resolve("8.8.8.8")
	if result.Resolved || result.UnresolvedReason != ReasonDatabaseNotConfigured {
		t.Fatalf("expected missing database reason, got %+v", result)
	}
	diagnostics := resolver.Diagnostics()
	if len(diagnostics) == 0 {
		t.Fatal("expected missing database diagnostic")
	}
}
