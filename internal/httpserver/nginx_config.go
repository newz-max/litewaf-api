package httpserver

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"litewaf-api/internal/model"
	"litewaf-api/internal/publish"
)

func (h handlers) getNginxConfigDraft(w http.ResponseWriter, r *http.Request) {
	item, err := h.app.Store.GetNginxConfigDraft(r.Context())
	if err == nil && !model.NginxConfigDraftHasAdvancedChanges(item) {
		item = nginxConfigDraftFromRuntime(filepath.Dir(h.app.Config.GatewayConfigPath), item)
	}
	h.writeItem(w, item, err)
}

func (h handlers) updateNginxConfigDraft(w http.ResponseWriter, r *http.Request) {
	var input model.NginxConfigDraft
	if !decodeJSON(w, r, &input) {
		return
	}
	input.UpdatedBy = currentActor(r).Username
	if input.Validation.Status == "" {
		input.Validation = model.NginxValidationResult{Status: model.NginxValidationStatusUnchecked}
	}
	item, err := h.app.Store.SaveNginxConfigDraft(r.Context(), input)
	h.auditMessage(r, "update", "nginx-config", 1, resultFromErr(err), nginxConfigAuditSummary(item), err)
	h.writeItem(w, item, err)
}

func (h handlers) validateNginxConfigDraft(w http.ResponseWriter, r *http.Request) {
	review, err := publish.BuildAdvancedNginxReview(
		r.Context(),
		h.app.Store,
		h.app.Config.GatewayConfigPath,
		h.app.Config.GatewayClientMaxBodySize,
		h.app.Config.NginxValidationCommand,
	)
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	draft, err := h.app.Store.GetNginxConfigDraft(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	draft.Validation = review.Validation
	draft.UpdatedBy = currentActor(r).Username
	if saved, saveErr := h.app.Store.SaveNginxConfigDraft(r.Context(), draft); saveErr == nil {
		draft = saved
	}
	writeJSON(w, http.StatusOK, envelope{
		"item":   draft,
		"review": review,
	})
}

func nginxConfigAuditSummary(item model.NginxConfigDraft) string {
	return boundedSummary("mode="+item.Mode, 256)
}

func nginxConfigDraftFromRuntime(runtimeDir string, fallback model.NginxConfigDraft) model.NginxConfigDraft {
	if content := readRuntimeNginxConfig(filepath.Join(runtimeDir, "nginx.conf")); content != "" {
		fallback.Mode = model.NginxConfigModeFull
		fallback.FullConfig = content
		fallback.Snippets = []model.NginxConfigSnippet{}
		if fallback.Validation.Status == "" {
			fallback.Validation = model.NginxValidationResult{Status: model.NginxValidationStatusUnchecked}
		}
		return fallback
	}

	snippets := readRuntimeNginxSnippets(filepath.Join(runtimeDir, "listeners", "snippets"))
	if !nginxSnippetsHaveContent(snippets) {
		return fallback
	}
	fallback.Mode = model.NginxConfigModeSnippets
	fallback.Snippets = snippets
	fallback.FullConfig = ""
	if fallback.Validation.Status == "" {
		fallback.Validation = model.NginxValidationResult{Status: model.NginxValidationStatusUnchecked}
	}
	return fallback
}

func readRuntimeNginxConfig(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readRuntimeNginxSnippets(snippetDir string) []model.NginxConfigSnippet {
	points := []string{
		model.NginxSnippetPointHTTP,
		model.NginxSnippetPointServer,
		model.NginxSnippetPointLocation,
	}
	snippets := make([]model.NginxConfigSnippet, 0, len(points))
	for _, point := range points {
		content := readRuntimeNginxConfig(filepath.Join(snippetDir, point+".conf"))
		snippets = append(snippets, model.NginxConfigSnippet{
			IncludePoint: point,
			Content:      stripGeneratedNginxSnippetHeader(content),
		})
	}
	return snippets
}

func stripGeneratedNginxSnippetHeader(content string) string {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "# generated from LiteWaf advanced nginx snippet draft")
	return strings.TrimSpace(content)
}

func nginxSnippetsHaveContent(snippets []model.NginxConfigSnippet) bool {
	for _, snippet := range snippets {
		if strings.TrimSpace(snippet.Content) != "" {
			return true
		}
	}
	return false
}
