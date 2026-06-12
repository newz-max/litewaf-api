package gatewayconfig

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	DefaultClientMaxBodySize = "50m"
	MaxClientBodySizeBytes   = 1024 * 1024 * 1024
)

var clientMaxBodySizePattern = regexp.MustCompile(`^[1-9][0-9]*([kKmMgG])?$`)

func NormalizeClientMaxBodySize(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = DefaultClientMaxBodySize
	}
	if !clientMaxBodySizePattern.MatchString(value) {
		return "", fmt.Errorf("gateway client max body size must match ^[1-9][0-9]*(k|K|m|M|g|G)?$")
	}
	bytes, ok := clientMaxBodySizeBytes(value)
	if !ok || bytes > MaxClientBodySizeBytes {
		return "", fmt.Errorf("gateway client max body size must be between 1 byte and 1g")
	}
	return strings.ToLower(value), nil
}

func clientMaxBodySizeBytes(value string) (int64, bool) {
	unit := byte(0)
	numberPart := value
	last := value[len(value)-1]
	if last < '0' || last > '9' {
		unit = last
		numberPart = value[:len(value)-1]
	}
	n, err := strconv.ParseInt(numberPart, 10, 64)
	if err != nil {
		return 0, false
	}
	switch unit {
	case 0:
		return n, true
	case 'k', 'K':
		return multiplyClientMaxBodySize(n, 1024)
	case 'm', 'M':
		return multiplyClientMaxBodySize(n, 1024*1024)
	case 'g', 'G':
		return multiplyClientMaxBodySize(n, 1024*1024*1024)
	default:
		return 0, false
	}
}

func multiplyClientMaxBodySize(n int64, multiplier int64) (int64, bool) {
	if n > MaxClientBodySizeBytes/multiplier {
		return MaxClientBodySizeBytes + 1, true
	}
	return n * multiplier, true
}
