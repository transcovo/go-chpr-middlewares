package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/transcovo/go-chpr-middlewares/fixtures"
)

func panicTestHandler(res http.ResponseWriter, req *http.Request) {
	panic(errors.New("some error"))
}

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	recoveryMiddleware := RecoveryMiddleware(&logrus.Logger{})
	assert.NotNil(t, recoveryMiddleware)
	wrappedHandler := recoveryMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	req := &http.Request{}

	wrappedHandler(recorder, req)
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)
}

func TestRecoveryMiddleware_Panic(t *testing.T) {
	recoveryMiddleware := RecoveryMiddleware(&logrus.Logger{})
	assert.NotNil(t, recoveryMiddleware)
	wrappedHandler := recoveryMiddleware(panicTestHandler)

	recorder := httptest.NewRecorder()
	req := &http.Request{}

	wrappedHandler(recorder, req)
	res := recorder.Result()
	assert.Equal(t, 500, res.StatusCode)
}
