package middleware

import (
	"net/http"
)

/*
Middleware is a function that wraps a handler and returns a new handler with more features.
*/
type Middleware func(http.HandlerFunc) http.HandlerFunc

/*
ChainMiddlewares chains the middlewares applied to the given http.HandlerFunc.
*/
func ChainMiddlewares(middlewares []Middleware, handler http.HandlerFunc) http.HandlerFunc {
	middlewaresCount := len(middlewares)
	for i := middlewaresCount - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
