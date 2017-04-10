package middleware

import (
	"net/http"
)

/*
Middleware is a function that wraps a handler and returns a new
handler with more features
*/
type Middleware func(http.HandlerFunc) http.HandlerFunc
