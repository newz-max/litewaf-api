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
	h.writeItem(w, item, err)
}

func (h handlers) getNginxEffectiveConfig(w http.ResponseWriter, r *http.Request) {
	item := nginxEffectiveConfigFromRuntime(filepath.Dir(h.app.Config.GatewayConfigPath))
	h.writeItem(w, item, nil)
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

func nginxEffectiveConfigFromRuntime(runtimeDir string) model.NginxEffectiveConfig {
	listenerDir := filepath.Join(runtimeDir, "listeners")
	configPath := filepath.Join(runtimeDir, "nginx.conf")
	item := model.NginxEffectiveConfig{
		Source:     "missing",
		Mode:       model.NginxConfigModeSnippets,
		Snippets:   []model.NginxConfigSnippet{},
		RuntimeDir: runtimeDir,
		ConfigPath: configPath,
	}
	if content := readRuntimeNginxConfig(configPath); content != "" {
		item.Source = "runtime_full"
		item.Mode = model.NginxConfigModeFull
		item.FullConfig = content
		item.Snippets = []model.NginxConfigSnippet{}
		return item
	}

	snippets := readRuntimeNginxSnippets(filepath.Join(listenerDir, "snippets"))
	if nginxSnippetsHaveContent(snippets) {
		item.Source = "runtime_snippets"
		item.Mode = model.NginxConfigModeSnippets
		item.Snippets = snippets
		return item
	}
	if runtimeListenerConfigExists(listenerDir) {
		item.Source = "generated_default"
		item.Mode = model.NginxConfigModeFull
		item.FullConfig = strings.TrimSpace(publish.DefaultNginxConfig(listenerDir))
		item.Snippets = []model.NginxConfigSnippet{}
		return item
	}
	return item
}

func readRuntimeNginxConfig(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func runtimeListenerConfigExists(listenerDir string) bool {
	for _, name := range []string{"applications.conf", "body-size.conf"} {
		if content := readRuntimeNginxConfig(filepath.Join(listenerDir, name)); content != "" {
			return true
		}
	}
	return false
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
