package middleware

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"strings"
)

/*
RawToken is an alias for string containing an authentication token
*/
type rawToken string

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
ErrInvalidToken returned when the token is ill-formatted, not matching the signature, expired
*/
var ErrInvalidToken = errors.New("invalid token")

/*
ErrInvalidClaims returned when the token claims do not respect the CP format
*/
var ErrInvalidClaims = errors.New("invalid token claims")

/*
ErrMissingPublicKey returned when the public key has not been passed
*/
var ErrMissingPublicKey = errors.New("missing public key")

/*
ErrInvalidAlgorithm is returned when the JWT algorithm does not match
*/
type ErrInvalidAlgorithm struct {
	Algorithm interface{}
}

func (err ErrInvalidAlgorithm) Error() string {
	return fmt.Sprintf("unexpected signing method: %v", err.Algorithm)
}

/*
EmptyToken is a shortcut for better readability
*/
const emptyToken = rawToken("")

/*
ContextKey created because Context cannot use plain strings
https://medium.com/@matryer/context-keys-in-go-5312346a868d
*/
type contextKey string

/*
String method added as suggested in https://medium.com/@matryer/context-keys-in-go-5312346a868d
*/
func (key contextKey) String() string {
	return fmt.Sprintf(`ContextKey("%s")`, string(key))
}

/*
TokenClaimsContextKey is used to store the token claims in the request context
(plain strings are not allowed as keys)
*/
const tokenClaimsContextKey = contextKey("TokenClaims")

var bearerRegex = regexp.MustCompile(`^Bearer\s(\S+)$`)

const publicKeysSeparator = ";\n"

/*
JwtAuthenticationMiddleware returns a middleware that:
- checks the Token from the Authorization header with a list of public keys (format "Bearer token")
- replies a 401 Unauthorized if it could not find a valid token (missing, expired, bad signature)
- parses the claims and add them to the request context if the token is valid
Panics if fails to parse the list of public keys
*/
func JwtAuthenticationMiddleware(publicKeysListAsString string, logger *logrus.Logger, isVerifyToken bool, ignoreExpiration bool) Middleware {
	if IsAuthIgnored() {
		logger.Warn("[JwtAuthenticationMiddleware] Authentication is ignored (IGNORE_AUTH sets to true)")
		return NoopMiddleware
	}
	publicKeys := []*rsa.PublicKey {}

	// Only parsing the publicKeys when isVerifyToken is true
	if isVerifyToken {
		publicKeys = parsePublicKeysList(publicKeysListAsString, logger)
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(res http.ResponseWriter, req *http.Request) {
			token := retrieveTokenFromHeader(req)

			parsed, err := getParsedToken(token, publicKeys, isVerifyToken, ignoreExpiration, logger)

			if err != nil {
				respond401Unauthorized(res)
				return
			}

			claims, _ := extractClaims(parsed)

			ctx := context.WithValue(req.Context(), tokenClaimsContextKey, claims)
			req = req.WithContext(ctx)

			next(res, req)
			return
		}
	}
}

func parsePublicKeysList(publicKeysListAsString string, logger *logrus.Logger) []*rsa.PublicKey {
	publicKeys := strings.Split(publicKeysListAsString, publicKeysSeparator)
	parsedPublicKeys := make([]*rsa.PublicKey, len(publicKeys))

	for i, publicKeyString := range publicKeys {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyString))
		if err != nil {
			logger.WithFields(logrus.Fields{
				"err":   err,
				"index": i,
			}).Error("[JwtAuthenticationMiddleware] Failed to parse public key")
			panic(err)
		}
		parsedPublicKeys[i] = publicKey
	}
	return parsedPublicKeys
}

/*
Tries to extract a Token from the Authorization header, expecting the format "Bearer token"
Returns an empty token if could not find a compliant token.
*/
func retrieveTokenFromHeader(req *http.Request) rawToken {
	if req == nil {
		return emptyToken
	}
	authHeader := req.Header.Get("Authorization")
	afterBearer := bearerRegex.FindStringSubmatch(authHeader)
	if len(afterBearer) < 2 {
		return emptyToken
	}
	return rawToken(afterBearer[1])
}

/*
Get the parsed value of the given token (without the signature)
*/
func getParsedToken(token rawToken, publicKeys []*rsa.PublicKey, isVerifyToken bool, ignoreExpiration bool, logger *logrus.Logger)(*jwt.Token, error){
	if !isVerifyToken {
		parsed, _, err :=  new(jwt.Parser).ParseUnverified(string(token), &TokenClaims{});

		if err != nil {
			return nil, err
		}

		parsed.Valid = true
		return parsed, nil
	}

	var errs error

	for _, publicKey := range publicKeys {
		parsed, err := validateToken(token, publicKey, isVerifyToken, ignoreExpiration)
		if err != nil {
			// Try to decode with the following key
			errs = err
			continue
		}

		return parsed, nil
	}

	return nil, errs
}

func validateToken(token rawToken, publicKey *rsa.PublicKey, isVerifyToken bool, ignoreExpiration bool) (*jwt.Token, error) {
	if publicKey == nil {
		return nil, ErrMissingPublicKey
	}
	parsed, err := jwt.ParseWithClaims(string(token), &TokenClaims{}, func(parsed *jwt.Token) (interface{}, error) {
		if _, ok := parsed.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, &ErrInvalidAlgorithm{parsed.Header["alg"]}
		}
		return publicKey, nil
	})

	v, _ := err.(*jwt.ValidationError)

	if err != nil && (v.Errors != jwt.ValidationErrorExpired || !ignoreExpiration ) {
		return nil, err
	}

	parsed.Valid = true;

	return parsed, nil
}

func extractClaims(parsed *jwt.Token) (*TokenClaims, error) {
	if !parsed.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := parsed.Claims.(*TokenClaims)

	if !ok {
		return nil, ErrInvalidClaims
	}
	return claims, nil
}

/*
Respond401Unauthorized handles the case when authentication fails
*/
func respond401Unauthorized(res http.ResponseWriter) {
	http.Error(res, "Unauthorized", http.StatusUnauthorized)
}

// GetClaims return the claims stored in the context of the request by the JwtAuthenticationMiddleware middlewate
func GetClaims(request *http.Request) *TokenClaims {
	claims := request.Context().Value(tokenClaimsContextKey)
	if claims, ok := claims.(*TokenClaims); ok {
		return claims
	}
	return nil
}
