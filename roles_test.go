package middleware

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/transcovo/go-chpr-middlewares/fixtures"
)

func TestRoleAuthorizationMiddleware_Success(t *testing.T) {
	employeeMiddleware := RoleAuthorizationMiddleware("cp:employee:")
	assert.NotNil(t, employeeMiddleware)
	wrappedHandler := employeeMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	req := &http.Request{}
	claims := &TokenClaims{Roles: []Role{{"cp:employee:tech:"}}}
	ctx := context.WithValue(req.Context(), tokenClaimsContextKey, claims)
	req = req.WithContext(ctx)
	wrappedHandler(recorder, req)
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)
}

func TestRoleAuthorizationMiddleware_Forbidden(t *testing.T) {
	employeeMiddleware := RoleAuthorizationMiddleware("cp:employee:")
	assert.NotNil(t, employeeMiddleware)
	wrappedHandler := employeeMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, &http.Request{})
	res := recorder.Result()
	assert.Equal(t, 403, res.StatusCode)
	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "Forbidden\n", string(body))
}

func TestRoleAuthorizationMiddleware_ChainedSuccess(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{})
	employeeMiddleware := RoleAuthorizationMiddleware("cp:client:rider:")
	wrappedHandler := jwtMiddleware(employeeMiddleware(fixtures.Fake200Handler))

	headers := http.Header{"Authorization": {"Bearer " + fixtures.Fixtures.TokenValidWithRiderRole}}
	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, &http.Request{Header: headers})
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)
}

func TestRoleAuthorizationMiddleware_ChainedForbidden(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{})
	employeeMiddleware := RoleAuthorizationMiddleware("cp:employee:")
	wrappedHandler := jwtMiddleware(employeeMiddleware(fixtures.Fake200Handler))

	headers := http.Header{"Authorization": {"Bearer " + fixtures.Fixtures.TokenValidWithRiderRole}}
	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, &http.Request{Header: headers})
	res := recorder.Result()
	assert.Equal(t, 403, res.StatusCode)
}

func TestMatchesRole_IsPrefix(t *testing.T) {
	patterns := []string{"cp:machine:", "cp:employee:"}
	roles := []Role{{"cp:employee:tech:"}}
	matches := matchesRoles(patterns, roles)
	assert.True(t, matches, "should be true when one role matches")
}

func TestMatchesRole_NoMatch(t *testing.T) {
	patterns := []string{"cp:machine:", "cp:employee:"}
	roles := []Role{{"cp:client:rider:"}}
	matches := matchesRoles(patterns, roles)
	assert.False(t, matches, "should be false when no match")
}

func TestRespond403Forbidden(t *testing.T) {
	recorder := httptest.NewRecorder()
	respond403Forbidden(recorder)
	res := recorder.Result()
	assert.Equal(t, 403, res.StatusCode)
	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "Forbidden\n", string(body))
}
