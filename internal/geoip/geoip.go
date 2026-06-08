package geoip

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

const (
	ReasonDatabaseNotConfigured = "geoip-database-not-configured"
	ReasonDatabaseLoadFailed    = "geoip-database-load-failed"
	ReasonInvalidIP             = "geoip-invalid-ip"
	ReasonReservedIP            = "geoip-reserved-ip"
	ReasonNoMatch               = "geoip-no-match"
)

type Options struct {
	DatabasePath      string
	ChinaDatabasePath string
	CacheSize         int
}

type Result struct {
	Resolved         bool
	CountryCode      string
	Country          string
	RegionCode       string
	Region           string
	City             string
	District         string
	Longitude        float64
	Latitude         float64
	Source           string
	SourceVersion    string
	UnresolvedReason string
}

type Resolver interface {
	Resolve(ip string) Result
	Diagnostics() []string
}

type resolver struct {
	mu              sync.RWMutex
	entries         []entry
	loadReason      string
	chinaSearcher   chinaRegionSearcher
	chinaLoadReason string
	cacheSize       int
	cache           map[string]Result
	cacheOrder      []string
	diagnostics     []string
}

type entry struct {
	prefix netip.Prefix
	start  netip.Addr
	end    netip.Addr
	result Result
}

type chinaRegionSearcher interface {
	Search(ip any) (string, error)
}

func NewResolver(options Options) Resolver {
	cacheSize := options.CacheSize
	if cacheSize == 0 {
		cacheSize = 2048
	}
	r := &resolver{
		cacheSize: cacheSize,
		cache:     map[string]Result{},
	}
	r.loadChinaDatabase(strings.TrimSpace(options.ChinaDatabasePath))
	path := strings.TrimSpace(options.DatabasePath)
	if path == "" {
		r.loadReason = ReasonDatabaseNotConfigured
		r.diagnostics = append(r.diagnostics, "GeoIP database is not configured; geographic report data will remain empty.")
		return r
	}
	if err := r.loadCSV(path); err != nil {
		r.loadReason = ReasonDatabaseLoadFailed
		r.diagnostics = append(r.diagnostics, fmt.Sprintf("GeoIP database could not be loaded: %s.", safeLoadError(err)))
		return r
	}
	r.diagnostics = append(r.diagnostics, fmt.Sprintf("GeoIP database loaded with %d ranges.", len(r.entries)))
	return r
}

func (r *resolver) Diagnostics() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.diagnostics...)
}

func (r *resolver) Resolve(ip string) Result {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Result{UnresolvedReason: ReasonInvalidIP}
	}
	addr = addr.Unmap()
	cacheKey := addr.String()
	if cached, ok := r.cached(cacheKey); ok {
		return cached
	}
	result := r.resolveAddr(addr)
	r.storeCache(cacheKey, result)
	return result
}

func (r *resolver) resolveAddr(addr netip.Addr) Result {
	if isReserved(addr) {
		return Result{UnresolvedReason: ReasonReservedIP}
	}
	r.mu.RLock()
	for _, item := range r.entries {
		if item.contains(addr) {
			result := item.result
			result.Resolved = true
			if result.Source == "" {
				result.Source = "geoip-csv"
			}
			r.mu.RUnlock()
			return r.enrichChinaResult(addr.String(), result)
		}
	}
	r.mu.RUnlock()
	if result, ok := r.resolveChinaOnly(addr.String()); ok {
		return result
	}
	if r.loadReason != "" {
		return Result{UnresolvedReason: r.loadReason}
	}
	return Result{UnresolvedReason: ReasonNoMatch}
}

func (r *resolver) loadChinaDatabase(path string) {
	if path == "" {
		return
	}
	content, err := xdb.LoadContentFromFile(path)
	if err != nil {
		r.chinaLoadReason = ReasonDatabaseLoadFailed
		r.diagnostics = append(r.diagnostics, fmt.Sprintf("GeoIP China database could not be loaded: %s.", safeLoadError(err)))
		return
	}
	searcher, err := xdb.NewWithBuffer(xdb.IPv4, content)
	if err != nil {
		r.chinaLoadReason = ReasonDatabaseLoadFailed
		r.diagnostics = append(r.diagnostics, "GeoIP China database could not be loaded: invalid or unsupported database.")
		return
	}
	r.chinaSearcher = searcher
	r.diagnostics = append(r.diagnostics, "GeoIP China database loaded with ip2region IPv4 data.")
}

func (r *resolver) enrichChinaResult(ip string, result Result) Result {
	if r.chinaSearcher == nil || !isChinaResult(result) {
		return result
	}
	region, err := r.chinaSearcher.Search(ip)
	if err != nil {
		return result
	}
	china, ok := parseChinaRegion(region)
	if !ok {
		return result
	}
	return mergeChinaRegion(result, china)
}

func (r *resolver) resolveChinaOnly(ip string) (Result, bool) {
	if r.chinaSearcher == nil {
		return Result{}, false
	}
	region, err := r.chinaSearcher.Search(ip)
	if err != nil {
		return Result{}, false
	}
	china, ok := parseChinaRegion(region)
	if !ok {
		return Result{}, false
	}
	return mergeChinaRegion(Result{
		Resolved:      true,
		CountryCode:   "CN",
		Country:       "中国",
		Source:        "ip2region",
		SourceVersion: "ip2region-v4",
	}, china), true
}

func (r *resolver) cached(key string) (Result, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result, ok := r.cache[key]
	return result, ok
}

func (r *resolver) storeCache(key string, result Result) {
	if r.cacheSize <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.cache[key]; !exists {
		r.cacheOrder = append(r.cacheOrder, key)
	}
	r.cache[key] = result
	for len(r.cacheOrder) > r.cacheSize {
		delete(r.cache, r.cacheOrder[0])
		r.cacheOrder = r.cacheOrder[1:]
	}
}

func (r *resolver) loadCSV(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true
	header, err := reader.Read()
	if err != nil {
		return err
	}
	columns := map[string]int{}
	for i, name := range header {
		columns[normalizeColumn(name)] = i
	}
	var entries []entry
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if emptyRow(row) {
			continue
		}
		item, ok, err := parseEntry(columns, row)
		if err != nil {
			return err
		}
		if ok {
			entries = append(entries, item)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].specificity() > entries[j].specificity()
	})
	r.entries = entries
	return nil
}

func parseEntry(columns map[string]int, row []string) (entry, bool, error) {
	var item entry
	cidr := field(columns, row, "cidr")
	if cidr != "" {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return entry{}, false, err
		}
		item.prefix = prefix.Masked()
	} else {
		start, err := netip.ParseAddr(field(columns, row, "start_ip"))
		if err != nil {
			return entry{}, false, err
		}
		end, err := netip.ParseAddr(field(columns, row, "end_ip"))
		if err != nil {
			return entry{}, false, err
		}
		item.start = start.Unmap()
		item.end = end.Unmap()
	}
	item.result = Result{
		CountryCode:   field(columns, row, "country_code"),
		Country:       firstNonEmpty(field(columns, row, "country"), field(columns, row, "country_name")),
		RegionCode:    field(columns, row, "region_code"),
		Region:        firstNonEmpty(field(columns, row, "region"), field(columns, row, "province")),
		City:          field(columns, row, "city"),
		District:      firstNonEmpty(field(columns, row, "district"), field(columns, row, "county")),
		Longitude:     parseFloat(field(columns, row, "longitude")),
		Latitude:      parseFloat(field(columns, row, "latitude")),
		Source:        firstNonEmpty(field(columns, row, "source"), "geoip-csv"),
		SourceVersion: firstNonEmpty(field(columns, row, "version"), field(columns, row, "source_version")),
	}
	return item, true, nil
}

func (item entry) contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	if item.prefix.IsValid() {
		return item.prefix.Contains(addr)
	}
	if !item.start.IsValid() || !item.end.IsValid() || item.start.BitLen() != addr.BitLen() || item.end.BitLen() != addr.BitLen() {
		return false
	}
	return compareAddr(item.start, addr) <= 0 && compareAddr(addr, item.end) <= 0
}

func (item entry) specificity() int {
	if item.prefix.IsValid() {
		return item.prefix.Bits()
	}
	return 0
}

func compareAddr(left netip.Addr, right netip.Addr) int {
	leftBytes := left.As16()
	rightBytes := right.As16()
	for i := 0; i < len(leftBytes); i++ {
		if leftBytes[i] < rightBytes[i] {
			return -1
		}
		if leftBytes[i] > rightBytes[i] {
			return 1
		}
	}
	return 0
}

func isReserved(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	reserved := []string{
		"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24",
		"192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
		"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	}
	for _, value := range reserved {
		prefix := netip.MustParsePrefix(value)
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func field(columns map[string]int, row []string, name string) string {
	index, ok := columns[normalizeColumn(name)]
	if !ok || index < 0 || index >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[index])
}

func normalizeColumn(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func parseFloat(value string) float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

type chinaRegion struct {
	CountryCode string
	Country     string
	Region      string
	City        string
}

func parseChinaRegion(value string) (chinaRegion, bool) {
	parts := strings.Split(value, "|")
	if len(parts) < 3 {
		return chinaRegion{}, false
	}
	country := strings.TrimSpace(parts[0])
	region := strings.TrimSpace(parts[1])
	city := strings.TrimSpace(parts[2])
	countryCode := ""
	if len(parts) >= 5 {
		countryCode = strings.ToUpper(strings.TrimSpace(parts[4]))
	}
	if countryCode != "CN" && country != "中国" && country != "中华人民共和国" {
		return chinaRegion{}, false
	}
	return chinaRegion{
		CountryCode: firstNonEmpty(countryCode, "CN"),
		Country:     firstNonEmpty(country, "中国"),
		Region:      region,
		City:        city,
	}, true
}

func mergeChinaRegion(result Result, china chinaRegion) Result {
	result.CountryCode = firstNonEmpty(result.CountryCode, china.CountryCode, "CN")
	result.Country = firstNonEmpty(result.Country, china.Country, "中国")
	result.Region = firstNonEmpty(result.Region, china.Region)
	result.City = firstNonEmpty(result.City, china.City)
	result.Source = appendToken(result.Source, "ip2region")
	result.SourceVersion = appendToken(result.SourceVersion, "ip2region-v4")
	return result
}

func isChinaResult(result Result) bool {
	value := strings.ToLower(strings.TrimSpace(firstNonEmpty(result.CountryCode, result.Country)))
	return value == "cn" || value == "china" || value == "中国" || value == "中华人民共和国"
}

func appendToken(value string, token string) string {
	value = strings.TrimSpace(value)
	token = strings.TrimSpace(token)
	if token == "" {
		return value
	}
	if value == "" {
		return token
	}
	for _, part := range strings.Split(value, ",") {
		if strings.TrimSpace(part) == token {
			return value
		}
	}
	return value + "," + token
}

func emptyRow(row []string) bool {
	for _, value := range row {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return true
}

func safeLoadError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "file does not exist"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	default:
		return "invalid or unsupported database"
	}
}
