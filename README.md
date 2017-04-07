# go-chpr-middlewares

[![CircleCI](https://circleci.com/gh/transcovo/go-chpr-middlewares.svg?style=shield)](https://circleci.com/gh/transcovo/go-chpr-middlewares)
[![codecov](https://codecov.io/gh/transcovo/go-chpr-middlewares/branch/master/graph/badge.svg)](https://codecov.io/gh/transcovo/go-chpr-middlewares)
[![GoDoc](https://godoc.org/github.com/transcovo/go-chpr-middlewares?status.svg)](https://godoc.org/github.com/transcovo/go-chpr-middlewares)

----------------- 

This library regroups HTTP middleware to be used in our golang servers.
A middleware is a function taking an `Handler` and returning an `Handler`,
where a `Handler` is a function with the signature `func(http.ResponseWriter, *http.Request)`.

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

### JwtAuthenticationMiddleware

```golang
import (
  middleware "github.com/transcovo/go-chpr-middlewares"
)

publicKeyString := getMyPublicKeyFromConfig()
authMiddleware := middleware.JwtAuthenticationMiddleware(publicKeyString)

func MyHandler(http.ResponseWriter, *http.Request) {
  /* does something */
}

wrappedHandler := authMiddleware(MyHandler)
```

Based on [the jwt go lib](https://github.com/dgrijalva/jwt-go).
 
## Misc 
 
The policy for this lib regarding vendoring is not to include any dependency.
The main reason for this is to avoid any conflict between your project and go-chpr-middlewares. 
