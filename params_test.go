package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func paramsGetter(req *http.Request) map[string]string {
	return map[string]string{"field": "value"}
}

var contextParamsChan chan map[string]string

func paramsTestHandler(res http.ResponseWriter, req *http.Request) {
	contextParamsChan <- req.Context().Value(ParamsContextKey).(map[string]string)
	res.WriteHeader(http.StatusOK)
}

func TestParamsMiddleware(t *testing.T) {
	contextParamsChan = make(chan map[string]string, 1)
	paramsMiddleware := ParamsMiddleware(paramsGetter)
	assert.NotNil(t, paramsMiddleware)
	wrappedHandler := paramsMiddleware(paramsTestHandler)

	recorder := httptest.NewRecorder()
	req := &http.Request{}

	wrappedHandler(recorder, req)
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)

	paramsContext := <-contextParamsChan
	assert.Equal(t, map[string]string{"field": "value"}, paramsContext)
}
