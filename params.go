package middleware

import (
	"context"
	"net/http"
)

/*
ParamsGetter is the function type used to get the request parameters in the request.
*/
type ParamsGetter func(*http.Request) map[string]string

/*
ParamsContextKey is used to store the request params in the request context (plain strings are not allowed as keys)
*/
const ParamsContextKey = ContextKey("params")

/*
ParamsMiddleware sets the request parameters in the request context.

The parameters are the variable values in the URLs.
*/
func ParamsMiddleware(paramsGetter ParamsGetter) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(res http.ResponseWriter, req *http.Request) {
			params := paramsGetter(req)

			ctx := context.WithValue(req.Context(), ParamsContextKey, params)
			req = req.WithContext(ctx)

			next(res, req)
		}
	}
}
