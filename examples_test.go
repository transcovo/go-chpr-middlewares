package middleware

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func registerHandler(string, http.HandlerFunc) {
}

func requestParamsGetter(*http.Request) map[string]string {
	return map[string]string{}
}

func myHandler(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func ExampleChainMiddlewares() {
	logger := &logrus.Logger{}

	handler := ChainMiddlewares([]Middleware{
		RecoveryMiddleware(logger),
		JwtAuthenticationMiddleware("some public key string", logger),
		RoleAuthorizationMiddleware("cp:client:rider:", "cp:employee:tech:"),
		ParamsMiddleware(requestParamsGetter),
	}, myHandler)

	registerHandler("/some/route", handler)
}
