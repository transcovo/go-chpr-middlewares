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

## Available middleware

```golang
import (
  middleware "github.com/transcovo/go-chpr-middlewares"
)
```

### JwtAuthenticationMiddleware

```golang
publicKeyString := getMyPublicKeyFromConfig()
authMiddleware := middleware.JwtAuthenticationMiddleware(publicKeyString)

func MyHandler(http.ResponseWriter, *http.Request) {
  /* does something */
}

wrappedHandler := authMiddleware(MyHandler)
```

Based on [the jwt go lib](https://github.com/dgrijalva/jwt-go).

### RoleAuthorizationMiddleware

* Important ! * Needs to be added after a JwtAuthenticationMiddleware to be able to access the user roles
from the token claims.

```golang
authMiddleware := middleware.JwtAuthenticationMiddleware(publicKeyString)
adminOnlyMiddleware := middleware.RoleAuthorizationMiddleware("cp:employee:", "cp:machine:")

func MyHandler(http.ResponseWriter, *http.Request) {
  /* does something */
}

wrappedHandler := authMiddleware(adminOnlyMiddleware(MyHandler))
```

## Misc

The policy for this lib regarding vendoring is not to include any dependency, unlike server code.
The main reason for this is to avoid any conflict between your project and go-chpr-middlewares.
For more explanations: https://peter.bourgon.org/go-best-practices-2016/#dependency-management

## Contribute and local installation

Dependencies for developing on this project will be automatically installed when running tests:
- via `./tools/test.sh`
- via `./tools/coverage.sh`
