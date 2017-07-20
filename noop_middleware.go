package middleware

import (
	"net/http"
	"os"
)

/*
IsAuthIgnored is true when the IGNORE_AUTH is properly set
*/
func IsAuthIgnored() bool {
	return os.Getenv("IGNORE_AUTH") == "true"
}

/*
NoopMiddleware is a middleware which simply pass along the handler function next()
*/
func NoopMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return next
}
