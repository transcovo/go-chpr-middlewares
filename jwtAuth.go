package middleware

import (
	"context"
	"crypto/rsa"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/transcovo/go-chpr-logger"
	"io"
	"net/http"
	"regexp"
)

/*
RawToken is an alias for string containing an authentication token
*/
type RawToken string

/*
Role is the struct of roles in CP tokens
*/
type Role struct {
	Name string `json:"name"`
}

/*
TokenClaims is a custom claim struct corresponding to Chauffeur Privé conventions
See example from https://godoc.org/github.com/dgrijalva/jwt-go#ParseWithClaims
*/
type TokenClaims struct {
	jwt.StandardClaims
	DisplayName string `json:"display_name"`
	Roles       []Role `json:"roles"`
}

/*
EmptyToken is a shortcut for better readability
*/
const EmptyToken = RawToken("")

/*
ContextKey created because Context cannot use plain strings
https://medium.com/@matryer/context-keys-in-go-5312346a868d
*/
type ContextKey string

/*
String method added as suggested in https://medium.com/@matryer/context-keys-in-go-5312346a868d
*/
func (key ContextKey) String() string {
	return "ContextKey(\"" + string(key) + "\")"
}

/*
TokenClaimsContextKey is used to store the token claims in the request context
(plain strings are not allowed as keys)
*/
const TokenClaimsContextKey = ContextKey("TokenClaims")

var bearerRegex = regexp.MustCompile("^Bearer\\s(\\S+)$")

/*
JwtAuthenticationMiddleware returns a middleware that:
- checks the Token from the Authorization header with a public key
- replies a 401 Unauthorized if could not find a valid token (missing, expired, bad signature)
- parses the claims and add them to the request context if the token is valid
Panics if fails to parse the public key
*/
func JwtAuthenticationMiddleware(publicKeyString string) Middleware {
	publicKey := parsePublicKey(publicKeyString)
	return func(next Handler) Handler {
		return func(res http.ResponseWriter, req *http.Request) {
			token := retrieveTokenFromHeader(req)
			claims, err := validateTokenAndExtractClaims(token, publicKey)
			if err != nil {
				respond401Unauthorized(res)
				return
			}
			ctx := context.WithValue(req.Context(), TokenClaimsContextKey, claims)
			req = req.WithContext(ctx)
			next(res, req)
		}
	}
}

func parsePublicKey(publicKeyString string) *rsa.PublicKey {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyString))
	if err != nil {
		logger.WithField("err", err).Error("[JwtAuthenticationMiddleware] Failed to parse public key")
		panic(err)
	}
	return publicKey
}

func retrieveTokenFromHeader(req *http.Request) RawToken {
	if req == nil {
		return EmptyToken
	}
	authHeader := req.Header.Get("Authorization")
	afterBearer := bearerRegex.FindStringSubmatch(authHeader)
	if len(afterBearer) < 2 {
		return EmptyToken
	}
	return RawToken(afterBearer[1])
}

func validateTokenAndExtractClaims(rawToken RawToken, publicKey *rsa.PublicKey) (*TokenClaims, error) {
	if publicKey == nil {
		return nil, errors.New("missing public key")
	}
	parsed, err := jwt.ParseWithClaims(string(rawToken), &TokenClaims{}, func(parsed *jwt.Token) (interface{}, error) {
		if _, ok := parsed.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", parsed.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	return extractClaims(parsed)
}

func extractClaims(parsed *jwt.Token) (*TokenClaims, error) {
	if !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := parsed.Claims.(*TokenClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

func respond401Unauthorized(res http.ResponseWriter) {
	res.WriteHeader(http.StatusUnauthorized)
	io.WriteString(res, "Unauthorized")
}
