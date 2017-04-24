package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/transcovo/go-chpr-middlewares/fixtures"
)

var testMiddlewarePosition chan int

func testMiddleware(position int) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(res http.ResponseWriter, req *http.Request) {
			testMiddlewarePosition <- position
			next(res, req)
		}
	}
}

func TestChainMiddlewares(t *testing.T) {
	testMiddlewarePosition = make(chan int, 3)
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

	for _, expected := range []int{3, 2, 1} {
		received := <-testMiddlewarePosition
		assert.Equal(t, expected, received)
	}
}
