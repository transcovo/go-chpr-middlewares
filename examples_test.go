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
		ParamsMiddleware(requestParamsGetter),
		RoleAuthorizationMiddleware("cp:client:rider:", "cp:employee:tech:"),
		JwtAuthenticationMiddleware("some public key string"),
		RecoveryMiddleware(),
	}, myHandler)

	registerHandler("/some/route", handler)
}
