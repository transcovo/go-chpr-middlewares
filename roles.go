package middleware

import (
	"net/http"
	"strings"
)

/*
RoleAuthorizationMiddleware checks if the JWT token from a request contains at least one
role matching a pattern from a list of patterns.
- If one role matches, call the next http handler
- If no match, reply a 403 Forbidden
To be plugged after JwtAuthenticationMiddleware.
*/
func RoleAuthorizationMiddleware(patterns ...string) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(res http.ResponseWriter, req *http.Request) {
			roles := extractRoles(req)
			if !matchesRoles(patterns, roles) {
				Respond403Forbidden(res)
				return
			}
			next(res, req)
		}
	}
}

func extractRoles(req *http.Request) []Role {
	roles := req.Context().Value(TokenClaimsContextKey)
	switch roles := roles.(type) {
	case []Role:
		return roles
	default:
		return nil
	}
}

func matchesRoles(patterns []string, roles []Role) bool {
	if len(roles) == 0 {
		return false
	}
	for _, pattern := range patterns {
		for _, role := range roles {
			if strings.HasPrefix(role.Name, pattern) {
				return true
			}
		}
	}
	return false
}

/*
Respond403Forbidden handles the case when authorization fails
*/
func Respond403Forbidden(res http.ResponseWriter) {
	http.Error(res, "Forbidden", http.StatusForbidden)
}
