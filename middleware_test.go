package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/transcovo/go-chpr-middlewares/fixtures"
)

var testMiddlewarePositionResult []int

func testMiddleware(position int) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(res http.ResponseWriter, req *http.Request) {
			testMiddlewarePositionResult = append(testMiddlewarePositionResult, position)
			next(res, req)
		}
	}
}

func TestChainMiddlewares(t *testing.T) {
	testMiddlewarePositionResult = make([]int, 0)
	recorder := httptest.NewRecorder()
	req := &http.Request{}

	wrappedHandler := ChainMiddlewares([]Middleware{
		testMiddleware(1),
		testMiddleware(2),
		testMiddleware(3),
	}, fixtures.Fake200Handler)

	wrappedHandler(recorder, req)
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)

	assert.Equal(t, []int{1, 2, 3}, testMiddlewarePositionResult)
}
