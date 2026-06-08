package geoip

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeChinaSearcher struct {
	regions map[string]string
}

func (f fakeChinaSearcher) Search(ip any) (string, error) {
	value, ok := f.regions[ip.(string)]
	if !ok {
		return "", errors.New("not found")
	}
	return value, nil
}

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

func TestResolverEnrichesChinaRegionWithIP2Region(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.csv")
	data := "cidr,country_code,country,region,city,district,longitude,latitude,source,version\n" +
		"120.227.116.0/24,CN,中国,,,,,,db-ip-lite,dbip-country\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write geoip db: %v", err)
	}
	resolver := NewResolver(Options{DatabasePath: path}).(*resolver)
	resolver.chinaSearcher = fakeChinaSearcher{regions: map[string]string{
		"120.227.116.170": "中国|广东省|广州市|移动|CN",
	}}

	result := resolver.Resolve("120.227.116.170")
	if !result.Resolved || result.Region != "广东省" || result.City != "广州市" || result.Source != "db-ip-lite,ip2region" || result.SourceVersion != "dbip-country,ip2region-v4" {
		t.Fatalf("unexpected enriched china result: %+v", result)
	}
}

func TestResolverUsesIP2RegionWhenCSVDoesNotMatch(t *testing.T) {
	resolver := NewResolver(Options{}).(*resolver)
	resolver.chinaSearcher = fakeChinaSearcher{regions: map[string]string{
		"120.227.116.170": "中国|广东省|广州市|移动|CN",
	}}

	result := resolver.Resolve("120.227.116.170")
	if !result.Resolved || result.CountryCode != "CN" || result.Country != "中国" || result.Region != "广东省" || result.City != "广州市" || result.UnresolvedReason != "" {
		t.Fatalf("unexpected china-only result: %+v", result)
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
