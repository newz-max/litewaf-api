package protectionrules

import "testing"

func TestValidatePathMatch(t *testing.T) {
	valid := []struct {
		name      string
		path      string
		pathMatch string
	}{
		{name: "exact", path: "/admin", pathMatch: "exact"},
		{name: "prefix", path: "/admin", pathMatch: "prefix"},
		{name: "glob", path: "/api/*/upload", pathMatch: "glob"},
		{name: "glob question", path: "/api/v?/upload", pathMatch: "glob"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePathMatch("test", tc.pathMatch, tc.path); err != nil {
				t.Fatalf("expected valid path match: %v", err)
			}
		})
	}

	invalid := []struct {
		name      string
		path      string
		pathMatch string
	}{
		{name: "relative", path: "admin", pathMatch: "prefix"},
		{name: "unknown", path: "/admin", pathMatch: "regex"},
		{name: "glob double star", path: "/api/**", pathMatch: "glob"},
		{name: "glob backslash", path: `/api/\*/upload`, pathMatch: "glob"},
		{name: "glob character class", path: "/api/[a]/upload", pathMatch: "glob"},
		{name: "glob brace", path: "/api/{a}/upload", pathMatch: "glob"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePathMatch("test", tc.pathMatch, tc.path); err == nil {
				t.Fatal("expected invalid path match")
			}
		})
	}
}
