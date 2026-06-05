package ipaccess

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"litewaf-api/internal/model"
)

const (
	Module = "ip-access-list"

	KindAllow = "allow"
	KindBlock = "block"

	TargetIP   = "ip"
	TargetCIDR = "cidr"

	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
)

func Normalize(item model.IPAccessListEntry) (model.IPAccessListEntry, error) {
	item.Name = strings.TrimSpace(item.Name)
	item.Kind = strings.ToLower(strings.TrimSpace(item.Kind))
	item.Target = strings.ToLower(strings.TrimSpace(item.Target))
	item.Value = strings.TrimSpace(item.Value)
	item.NormalizedValue = ""
	item.IPFamily = ""
	item.Description = bounded(strings.TrimSpace(item.Description), 512)
	item.ConflictKey = ""
	if item.Kind == "" {
		item.Kind = KindBlock
	}
	if item.Target == "" {
		if strings.Contains(item.Value, "/") {
			item.Target = TargetCIDR
		} else {
			item.Target = TargetIP
		}
	}
	if item.Priority == 0 {
		item.Priority = 100
	}
	if item.SiteID < 0 {
		return item, errors.New("ip access-list site_id cannot be negative")
	}
	if !oneOf(item.Kind, KindAllow, KindBlock) {
		return item, errors.New("ip access-list kind must be allow or block")
	}
	if !oneOf(item.Target, TargetIP, TargetCIDR) {
		return item, errors.New("ip access-list target must be ip or cidr")
	}
	if item.Value == "" {
		return item, errors.New("ip access-list value is required")
	}
	if item.Priority < 0 {
		return item, errors.New("ip access-list priority cannot be negative")
	}

	switch item.Target {
	case TargetIP:
		addr, err := netip.ParseAddr(item.Value)
		if err != nil {
			return item, errors.New("ip access-list ip value is invalid")
		}
		item.NormalizedValue = normalizedAddr(addr)
		item.IPFamily = family(addr)
		item.PrefixLength = bitLength(addr)
	case TargetCIDR:
		prefix, err := netip.ParsePrefix(item.Value)
		if err != nil {
			return item, errors.New("ip access-list cidr value is invalid")
		}
		prefix = prefix.Masked()
		addr := prefix.Addr()
		item.NormalizedValue = normalizedAddr(addr)
		item.IPFamily = family(addr)
		item.PrefixLength = prefix.Bits()
		if item.PrefixLength < 0 || item.PrefixLength > bitLength(addr) {
			return item, errors.New("ip access-list cidr prefix is invalid")
		}
	}
	item.ConflictKey = fmt.Sprintf("site:%d|%s|%s|%s/%d", item.SiteID, item.Target, item.IPFamily, item.NormalizedValue, item.PrefixLength)
	return item, nil
}

func Validate(item model.IPAccessListEntry) error {
	normalized, err := Normalize(item)
	if err != nil {
		return err
	}
	if normalized.Name == "" {
		return errors.New("ip access-list name is required")
	}
	if item.NormalizedValue != "" && item.NormalizedValue != normalized.NormalizedValue {
		return errors.New("ip access-list normalized_value is inconsistent")
	}
	if item.IPFamily != "" && item.IPFamily != normalized.IPFamily {
		return errors.New("ip access-list ip_family is inconsistent")
	}
	if item.PrefixLength != 0 && item.PrefixLength != normalized.PrefixLength {
		return errors.New("ip access-list prefix_length is inconsistent")
	}
	return nil
}

func ScopeKey(siteID int64) string {
	if siteID > 0 {
		return fmt.Sprintf("site:%d", siteID)
	}
	return "global"
}

func bounded(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func family(addr netip.Addr) string {
	if addr.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

func normalizedAddr(addr netip.Addr) string {
	if addr.Is4() {
		return addr.String()
	}
	raw := addr.As16()
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])
}

func bitLength(addr netip.Addr) int {
	if addr.Is4() {
		return 32
	}
	return 128
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
