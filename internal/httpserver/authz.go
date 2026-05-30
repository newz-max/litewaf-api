package httpserver

import (
	"context"
	"net/http"
	"strings"

	"litewaf-api/internal/auth"
)

type actorContextKey struct{}

const (
	roleAdmin    = "admin"
	roleAuditor  = "auditor"
	roleReadonly = "readonly"

	permissionRead    = "read"
	permissionWrite   = "write"
	permissionAudit   = "audit"
	permissionPublish = "publish"
)

type actor struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (h handlers) require(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing access token")
			return
		}
		claims, err := auth.ParseToken(h.app.Config.AuthTokenSecret, strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid access token")
			return
		}
		current := actor{UserID: claims.UserID, Username: claims.Subject, Role: claims.Role}
		if !allows(current.Role, permission) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		ctx := context.WithValue(r.Context(), actorContextKey{}, current)
		next(w, r.WithContext(ctx))
	}
}

func currentActor(r *http.Request) actor {
	if value, ok := r.Context().Value(actorContextKey{}).(actor); ok {
		return value
	}
	return actor{Username: "anonymous", Role: "anonymous"}
}

func allows(role string, permission string) bool {
	switch role {
	case roleAdmin:
		return true
	case roleAuditor:
		return permission == permissionRead || permission == permissionAudit
	case roleReadonly:
		return permission == permissionRead
	default:
		return false
	}
}

func isWriteMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete
}
