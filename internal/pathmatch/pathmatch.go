package pathmatch

import (
	"fmt"
	"path"
	"strings"
)

const (
	Exact  = "exact"
	Prefix = "prefix"
	Glob   = "glob"
)

func Is(value string) bool {
	return value == Exact || value == Prefix || value == Glob
}

func IsGlobValid(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") {
		return false
	}
	if strings.Contains(value, "**") || strings.Contains(value, "\\") || strings.ContainsAny(value, "[]{}") {
		return false
	}
	_, err := path.Match(value, value)
	return err == nil
}

func Validate(scope string, value string, routePath string) error {
	if !strings.HasPrefix(routePath, "/") {
		return fmt.Errorf("%s path must start with /", scope)
	}
	if !Is(value) {
		return fmt.Errorf("%s path_match must be exact, prefix, or glob", scope)
	}
	if value == Glob && !IsGlobValid(routePath) {
		return fmt.Errorf("%s glob path is invalid", scope)
	}
	return nil
}
