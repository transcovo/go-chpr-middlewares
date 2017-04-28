package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func paramsGetter(req *http.Request) map[string]string {
	return map[string]string{"field": "value"}
}

var contextParamsResult map[string]string

func paramsTestHandler(res http.ResponseWriter, req *http.Request) {
	contextParamsResult = req.Context().Value(paramsContextKey).(map[string]string)
	res.WriteHeader(http.StatusOK)
}

func TestParamsMiddleware(t *testing.T) {
	contextParamsResult = make(map[string]string)
	paramsMiddleware := ParamsMiddleware(paramsGetter)
	assert.NotNil(t, paramsMiddleware)
	wrappedHandler := paramsMiddleware(paramsTestHandler)

	recorder := httptest.NewRecorder()
	req := &http.Request{}

	wrappedHandler(recorder, req)
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)

	assert.Equal(t, map[string]string{"field": "value"}, contextParamsResult)
}

func TestGetParamsFromRequest_WithParams(t *testing.T) {
	params := map[string]string{"field": "value"}

	req := &http.Request{}
	ctx := context.WithValue(req.Context(), paramsContextKey, params)
	req = req.WithContext(ctx)

	resParams := GetParamsFromRequest(req)
	assert.Equal(t, params, resParams)
}

func TestGetParamsFromRequest_WithoutParams(t *testing.T) {
	req := &http.Request{}

	resParams := GetParamsFromRequest(req)
	assert.Equal(t, map[string]string{}, resParams)
}
