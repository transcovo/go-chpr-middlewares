package middleware

import "net/http"

func registerHandler(string, http.HandlerFunc) {
}

func requestParamsGetter(*http.Request) map[string]string {
	return map[string]string{}
}

func myHandler(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func ExampleChainMiddlewares() {
	handler := ChainMiddlewares([]Middleware{
		RecoveryMiddleware(),
		JwtAuthenticationMiddleware("some public key string"),
		RoleAuthorizationMiddleware("cp:client:rider:", "cp:employee:tech:"),
		ParamsMiddleware(requestParamsGetter),
	}, myHandler)

	registerHandler("/some/route", handler)
}
