# go-chpr-middlewares

[![CircleCI](https://circleci.com/gh/transcovo/go-chpr-middlewares.svg?style=shield)](https://circleci.com/gh/transcovo/go-chpr-middlewares)
[![codecov](https://codecov.io/gh/transcovo/go-chpr-middlewares/branch/master/graph/badge.svg)](https://codecov.io/gh/transcovo/go-chpr-middlewares)
[![GoDoc](https://godoc.org/github.com/transcovo/go-chpr-middlewares?status.svg)](https://godoc.org/github.com/transcovo/go-chpr-middlewares)

-----------------

This library regroups HTTP middleware to be used in our golang servers.
A middleware is a function taking a `http.HandlerFunc` and returning a `http.HandlerFunc`.
`http.HandlerFunc` is a function with the signature `func(http.ResponseWriter, *http.Request)`.
It implements the interface `http.Handler`.

See the [godoc](https://godoc.org/github.com/transcovo/go-chpr-middlewares)

## Requirements

Minimum Go version: 1.7

## Installation

if using govendor
```bash
govendor fetch -u github.com/transcovo/go-chpr-middlewares
```

standard way (not recommended)
```bash
go get -u github.com/transcovo/go-chpr-middlewares
```

## Usage

### ChainMiddlewares

This function is a helper to apply a list of middlewares to a given handler.

**Note**:  The middlewares are applied in the reverse order, which means that the first one in the list will be the last one applied on the handler, and the first one to be executed when handling a request.

Example:
```golang
import (
  "github.com/transcovo/go-chpr-middlewares"
)

func main() {
  // when handling a request, `RecoveryMiddleware` will be called first, then
  // `JwtAuthenticationMiddleware`, `RoleAuthorizationMiddleware` and `ParamsMiddleware`, and then
  // the handler will be called.
  handler := middleware.ChainMiddlewares([]middleware.Middleware{
    middleware.RecoveryMiddleware(someLogger),
    middleware.JwtAuthenticationMiddleware("some public key string", someLogger),
    middleware.RoleAuthorizationMiddleware("cp:client:rider:", "cp:employee:tech:"),
    middleware.ParamsMiddleware(requestParamsGetter),
  }, myHandler)

  registerHandler("/some/route", handler)
}
```

### Available middlewares

#### JwtAuthenticationMiddleware

```golang
logger := getMyLogger()
publicKeyString := getMyPublicKeyFromConfig()
authMiddleware := middleware.JwtAuthenticationMiddleware(publicKeyString, logger)

func MyHandler(http.ResponseWriter, *http.Request) {
  /* does something */
}

wrappedHandler := authMiddleware(MyHandler)
```

Based on [the jwt go lib](https://github.com/dgrijalva/jwt-go).

#### RoleAuthorizationMiddleware

* Important ! * Needs to be added after a JwtAuthenticationMiddleware to be able to access the user roles
from the token claims.

```golang
logger := getMyLogger()
authMiddleware := middleware.JwtAuthenticationMiddleware(publicKeyString, logger)
adminOnlyMiddleware := middleware.RoleAuthorizationMiddleware("cp:employee:", "cp:machine:")

func MyHandler(http.ResponseWriter, *http.Request) {
  /* does something */
}

wrappedHandler := authMiddleware(adminOnlyMiddleware(MyHandler))
```

#### ParamsMiddleware

Middleware used to set the request params in the request context.

The controller will have to use `GetParamsFromRequest` to get the params in the request.

It will mainly be used with [mux](https://github.com/gorilla/mux).

```golang
paramsMiddleware := middleware.ParamsMiddleware(mux.Vars)

func MyHandler(http.ResponseWriter, req *http.Request) {
  params := GetParamsFromRequest(req)
  /* does something */
}

wrappedHandler := paramsMiddleware(MyHandler)
```

#### RecoveryMiddleware

Middleware used to catch panics that can happen during the request handling.

On panic, this middleware will catch it and reply a 500 to the client.

```golang
logger := getMyLogger()
recoveryMiddleware := middleware.RecoveryMiddleware(logger)

func MyHandler(http.ResponseWriter, *http.Request) {
  /* does something */
}

wrappedHandler := recoveryMiddleware(MyHandler)
```

## Misc

The policy for this lib regarding vendoring is not to include any dependency, unlike server code.
The main reason for this is to avoid any conflict between your project and go-chpr-middlewares.
For more explanations: https://peter.bourgon.org/go-best-practices-2016/#dependency-management

## Contribute and local installation

Dependencies for developing on this project will be automatically installed when running tests:
- via `./tools/test.sh`
- via `./tools/coverage.sh`
