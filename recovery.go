package middleware

import (
	"net/http"

	"github.com/Sirupsen/logrus"
)

/*
RecoveryMiddleware catches the panics that happen during a request execution.

On panic, it sends a 500 to the client.
*/
func RecoveryMiddleware(logger *logrus.Logger) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(res http.ResponseWriter, req *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.WithField("err", err).Error("[Recovery Middleware] Recovered panic from handler")

					res.WriteHeader(http.StatusInternalServerError)
				}
			}()

			next(res, req)
		}
	}
}
