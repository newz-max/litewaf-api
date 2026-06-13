package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	NginxConfigModeSnippets = "snippets"
	NginxConfigModeFull     = "full"

	NginxSnippetPointHTTP     = "http"
	NginxSnippetPointServer   = "server"
	NginxSnippetPointLocation = "location"

	NginxValidationStatusUnchecked   = "unchecked"
	NginxValidationStatusPassed      = "passed"
	NginxValidationStatusFailed      = "failed"
	NginxValidationStatusUnavailable = "unavailable"
)

type NginxConfigDraft struct {
	Mode        string                `json:"mode"`
	Snippets    []NginxConfigSnippet  `json:"snippets"`
	FullConfig  string                `json:"full_config,omitempty"`
	Validation  NginxValidationResult `json:"validation"`
	UpdatedBy   string                `json:"updated_by"`
	UpdatedAt   time.Time             `json:"updated_at"`
	PublishedAt *time.Time            `json:"published_at,omitempty"`
}

type NginxEffectiveConfig struct {
	Source     string               `json:"source"`
	Mode       string               `json:"mode"`
	Snippets   []NginxConfigSnippet `json:"snippets"`
	FullConfig string               `json:"full_config,omitempty"`
	RuntimeDir string               `json:"runtime_dir,omitempty"`
	ConfigPath string               `json:"config_path,omitempty"`
}

type NginxConfigSnippet struct {
	IncludePoint string `json:"include_point"`
	Content      string `json:"content"`
}

type NginxValidationResult struct {
	Status      string   `json:"status"`
	Command     string   `json:"command,omitempty"`
	Message     string   `json:"message,omitempty"`
	Diagnostics []string `json:"diagnostics,omitempty"`
	ValidatedAt string   `json:"validated_at,omitempty"`
}

func EmptyNginxConfigDraft() NginxConfigDraft {
	return NginxConfigDraft{
		Mode:       NginxConfigModeSnippets,
		Snippets:   []NginxConfigSnippet{},
		Validation: NginxValidationResult{Status: NginxValidationStatusUnchecked},
	}
}

func NormalizeNginxConfigDraft(draft *NginxConfigDraft) {
	draft.Mode = strings.ToLower(strings.TrimSpace(draft.Mode))
	if draft.Mode == "" {
		draft.Mode = NginxConfigModeSnippets
	}
	draft.UpdatedBy = strings.TrimSpace(draft.UpdatedBy)
	filtered := make([]NginxConfigSnippet, 0, len(draft.Snippets))
	for _, snippet := range draft.Snippets {
		snippet.IncludePoint = strings.ToLower(strings.TrimSpace(snippet.IncludePoint))
		snippet.Content = strings.TrimSpace(snippet.Content)
		if snippet.IncludePoint == "" && snippet.Content == "" {
			continue
		}
		filtered = append(filtered, snippet)
	}
	draft.Snippets = filtered
	draft.FullConfig = strings.TrimSpace(draft.FullConfig)
	draft.Validation.Status = normalizeNginxValidationStatus(draft.Validation.Status)
}

func ValidateNginxConfigDraft(draft NginxConfigDraft) error {
	if draft.Mode != NginxConfigModeSnippets && draft.Mode != NginxConfigModeFull {
		return errors.New("nginx config mode must be snippets or full")
	}
	for _, snippet := range draft.Snippets {
		if !ValidNginxSnippetPoint(snippet.IncludePoint) {
			return fmt.Errorf("invalid nginx snippet include point %q", snippet.IncludePoint)
		}
	}
	return nil
}

func NginxConfigDraftHasAdvancedChanges(draft NginxConfigDraft) bool {
	if draft.Mode == NginxConfigModeFull && strings.TrimSpace(draft.FullConfig) != "" {
		return true
	}
	for _, snippet := range draft.Snippets {
		if strings.TrimSpace(snippet.Content) != "" {
			return true
		}
	}
	return false
}

func ValidNginxSnippetPoint(value string) bool {
	switch value {
	case NginxSnippetPointHTTP, NginxSnippetPointServer, NginxSnippetPointLocation:
		return true
	default:
		return false
	}
}

func normalizeNginxValidationStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case NginxValidationStatusPassed, NginxValidationStatusFailed, NginxValidationStatusUnavailable:
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return NginxValidationStatusUnchecked
	}
}
