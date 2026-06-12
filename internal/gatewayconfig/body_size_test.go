package gatewayconfig

import (
	"strings"
	"testing"
)

func TestNormalizeClientMaxBodySize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "default", in: "", want: "50m"},
		{name: "megabytes", in: "50m", want: "50m"},
		{name: "uppercase", in: "1G", want: "1g"},
		{name: "kilobytes", in: "512k", want: "512k"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeClientMaxBodySize(tt.in)
			if err != nil {
				t.Fatalf("expected %q to be valid: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeClientMaxBodySize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeClientMaxBodySizeRejectsInvalidValues(t *testing.T) {
	tests := []string{
		"0",
		"-1m",
		"1.5m",
		"50m; lua_code_cache off;",
		"2g",
		"9999999999g",
		strings.Repeat("9", 4096),
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if _, err := NormalizeClientMaxBodySize(tt); err == nil {
				t.Fatalf("expected %q to be invalid", tt)
			}
		})
	}
}
