package middleware

import (
	"net/http"
)

/*
Handler is the simplest possible signature compatible with net/http
*/
type Handler func(http.ResponseWriter, *http.Request)

/*
Middleware is a function that wraps a handler and returns a new
handler with more features
*/
type Middleware func(Handler) Handler
