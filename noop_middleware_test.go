package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/transcovo/go-chpr-middlewares/fixtures"
)

func TestIsAuthIgnored_EnvVarSet(t *testing.T) {
	os.Setenv("IGNORE_AUTH", "true")
	defer os.Setenv("IGNORE_AUTH", "")

	assert.Equal(t, true, IsAuthIgnored())
}

func TestIsAuthIgnored_EnvVarNotSet(t *testing.T) {
	os.Setenv("IGNORE_AUTH", "")

	assert.Equal(t, false, IsAuthIgnored())
}

func TestNoopMiddleware(t *testing.T) {
	wrappedHandler := NoopMiddleware(fixtures.Fake200Handler)
	// check if NoopMiddleware returns the same function
	assert.Equal(t,
		reflect.ValueOf(fixtures.Fake200Handler).Pointer(),
		reflect.ValueOf(wrappedHandler).Pointer(),
	)

	recorder := httptest.NewRecorder()
	req := &http.Request{}
	wrappedHandler(recorder, req)
	res := recorder.Result()

	assert.Equal(t, 200, res.StatusCode)
}
