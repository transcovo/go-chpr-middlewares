package middleware

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/transcovo/go-chpr-middlewares/fixtures"
)

func TestMiddleware_Unauthorized(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey)
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)
	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, &http.Request{})
	res := recorder.Result()
	assert.Equal(t, 401, res.StatusCode)
	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "Unauthorized\n", string(body))
}

func TestMiddleware_ValidToken(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey)
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	headers := http.Header{"Authorization": {"Bearer " + fixtures.Fixtures.TokenValidWithRiderRole}}
	wrappedHandler(recorder, &http.Request{Header: headers})
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)
}

func TestParsePublicKey_ValidKey(t *testing.T) {
	parsed := parsePublicKey(fixtures.Fixtures.RawRsaPublicKey)
	assert.Equal(t, fixtures.GetRsaPublicKey(), parsed)
}

func TestParsePublicKey_InvalidKey(t *testing.T) {
	parseInvalidKey := func() {
		parsePublicKey("not a key !")
	}
	assert.Panics(t, parseInvalidKey)
}

func TestRetrieveTokenFromHeader_Nil(t *testing.T) {
	token := retrieveTokenFromHeader(nil)
	assert.Equal(t, EmptyToken, token)
}

func TestRetrieveTokenFromHeader_NoHeader(t *testing.T) {
	token := retrieveTokenFromHeader(&http.Request{})
	assert.Equal(t, EmptyToken, token)
}

func TestRetrieveTokenFromHeader_NoBearer(t *testing.T) {
	headers := http.Header{"Authorization": {"my_token"}}
	token := retrieveTokenFromHeader(&http.Request{Header: headers})
	assert.Equal(t, EmptyToken, token)
}

func TestRetrieveTokenFromHeader_Success(t *testing.T) {
	headers := http.Header{"Authorization": {"Bearer my_token"}}
	token := retrieveTokenFromHeader(&http.Request{Header: headers})
	assert.Equal(t, RawToken("my_token"), token)
}

func TestValidateTokenAndExtractClaims_NoRsaKey(t *testing.T) {
	validToken := RawToken(fixtures.Fixtures.TokenValidWithRiderRole)
	claims, err := validateTokenAndExtractClaims(validToken, nil)
	assert.EqualError(t, err, "missing public key")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_Empty(t *testing.T) {
	claims, err := validateTokenAndExtractClaims(EmptyToken, fixtures.GetRsaPublicKey())
	assert.EqualError(t, err, "token contains an invalid number of segments")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_InvalidAlgorithm(t *testing.T) {
	token := RawToken(fixtures.Fixtures.TokenWithInvalidAlgorithm)
	claims, err := validateTokenAndExtractClaims(token, fixtures.GetRsaPublicKey())
	assert.EqualError(t, err, "unexpected signing method: HS256")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_InvalidSignature(t *testing.T) {
	token := RawToken(fixtures.Fixtures.TokenWithInvalidSignature)
	claims, err := validateTokenAndExtractClaims(token, fixtures.GetRsaPublicKey())
	assert.EqualError(t, err, "crypto/rsa: verification error")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_Expired(t *testing.T) {
	token := RawToken(fixtures.Fixtures.TokenExpired)
	claims, err := validateTokenAndExtractClaims(token, fixtures.GetRsaPublicKey())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired by")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_ValidToken(t *testing.T) {
	token := RawToken(fixtures.Fixtures.TokenValidWithRiderRole)
	claims, err := validateTokenAndExtractClaims(token, fixtures.GetRsaPublicKey())
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, []Role{{"cp:client:rider:"}}, claims.Roles)
}

func TestExtractClaims_InvalidToken(t *testing.T) {
	jwtToken := &jwt.Token{Valid: false}
	claims, err := extractClaims(jwtToken)
	assert.EqualError(t, err, "invalid token")
	assert.Nil(t, claims)
}

func TestExtractClaims_InvalidClaims(t *testing.T) {
	jwtToken := &jwt.Token{Valid: true}
	claims, err := extractClaims(jwtToken)
	assert.EqualError(t, err, "invalid token claims")
	assert.Nil(t, claims)
}

func TestRespond401Unauthorized(t *testing.T) {
	recorder := httptest.NewRecorder()
	Respond401Unauthorized(recorder)
	res := recorder.Result()
	assert.Equal(t, 401, res.StatusCode)
	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "Unauthorized\n", string(body))
}

func TestContextKey_String(t *testing.T) {
	keyString := TokenClaimsContextKey.String()
	assert.Equal(t, `ContextKey("TokenClaims")`, keyString)
}
