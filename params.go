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
paramsContextKey is used to store the request params in the request context (plain strings are not allowed as keys)
*/
const paramsContextKey = contextKey("params")

/*
ParamsMiddleware sets the request parameters in the request context.

The parameters are the variable values in the URLs.
*/
func ParamsMiddleware(paramsGetter ParamsGetter) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(res http.ResponseWriter, req *http.Request) {
			params := paramsGetter(req)

			ctx := context.WithValue(req.Context(), paramsContextKey, params)
			req = req.WithContext(ctx)

			next(res, req)
		}
	}
}

/*
GetParamsFromRequest returns the params set in the request context in the ParamsMiddleware.

This is to be called in the controllers.
*/
func GetParamsFromRequest(req *http.Request) map[string]string {
	params := req.Context().Value(paramsContextKey)
	if params != nil {
		return params.(map[string]string)
	}
	return map[string]string{}
}
