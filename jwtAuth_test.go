package middleware

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/transcovo/go-chpr-middlewares/fixtures"
)

func TestMiddleware_Unauthorized(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{})
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)
	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, &http.Request{})
	res := recorder.Result()
	assert.Equal(t, 401, res.StatusCode)
	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "Unauthorized\n", string(body))
}

func TestMiddleware_ValidToken(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{})
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	headers := http.Header{"Authorization": {"Bearer " + fixtures.Fixtures.TokenValidWithRiderRole}}
	wrappedHandler(recorder, &http.Request{Header: headers})
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)
}

func TestMiddleWare_StoreInformationInRequestcontext(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{})
	modifiedRequest := &http.Request{}
	fakeHandler := func(res http.ResponseWriter, req *http.Request) {
		modifiedRequest = req
	}

	wrappedHandler := jwtMiddleware(fakeHandler)
	headers := http.Header{"Authorization": {"Bearer " + fixtures.Fixtures.TokenValidWithRiderRole}}
	initialRequest := &http.Request{Header: headers}
	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, initialRequest)

	storedClaims := modifiedRequest.Context().Value(tokenClaimsContextKey).(*TokenClaims)
	assert.Equal(t, []Role{{Name: "cp:client:rider:"}}, storedClaims.Roles)
	assert.Equal(t, "Alfred Bernard", storedClaims.DisplayName)
}

func TestParsePublicKey_ValidKey(t *testing.T) {
	parsed := parsePublicKey(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{})
	assert.Equal(t, fixtures.GetRsaPublicKey(), parsed)
}

func TestParsePublicKey_InvalidKey(t *testing.T) {
	parseInvalidKey := func() {
		parsePublicKey("not a key !", &logrus.Logger{})
	}
	assert.Panics(t, parseInvalidKey)
}

func TestRetrieveTokenFromHeader_Nil(t *testing.T) {
	token := retrieveTokenFromHeader(nil)
	assert.Equal(t, emptyToken, token)
}

func TestRetrieveTokenFromHeader_NoHeader(t *testing.T) {
	token := retrieveTokenFromHeader(&http.Request{})
	assert.Equal(t, emptyToken, token)
}

func TestRetrieveTokenFromHeader_NoBearer(t *testing.T) {
	headers := http.Header{"Authorization": {"my_token"}}
	token := retrieveTokenFromHeader(&http.Request{Header: headers})
	assert.Equal(t, emptyToken, token)
}

func TestRetrieveTokenFromHeader_Success(t *testing.T) {
	headers := http.Header{"Authorization": {"Bearer my_token"}}
	token := retrieveTokenFromHeader(&http.Request{Header: headers})
	assert.Equal(t, rawToken("my_token"), token)
}

func TestValidateTokenAndExtractClaims_NoRsaKey(t *testing.T) {
	validToken := rawToken(fixtures.Fixtures.TokenValidWithRiderRole)
	claims, err := validateTokenAndExtractClaims(validToken, nil)
	assert.EqualError(t, err, "missing public key")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_Empty(t *testing.T) {
	claims, err := validateTokenAndExtractClaims(emptyToken, fixtures.GetRsaPublicKey())
	assert.EqualError(t, err, "token contains an invalid number of segments")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_InvalidAlgorithm(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenWithInvalidAlgorithm)
	claims, err := validateTokenAndExtractClaims(token, fixtures.GetRsaPublicKey())
	assert.EqualError(t, err, "unexpected signing method: HS256")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_InvalidSignature(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenWithInvalidSignature)
	claims, err := validateTokenAndExtractClaims(token, fixtures.GetRsaPublicKey())
	assert.EqualError(t, err, "crypto/rsa: verification error")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_Expired(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenExpired)
	claims, err := validateTokenAndExtractClaims(token, fixtures.GetRsaPublicKey())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired by")
	assert.Nil(t, claims)
}

func TestValidateTokenAndExtractClaims_ValidToken(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenValidWithRiderRole)
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
	respond401Unauthorized(recorder)
	res := recorder.Result()
	assert.Equal(t, 401, res.StatusCode)
	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "Unauthorized\n", string(body))
}

func TestContextKey_String(t *testing.T) {
	keyString := tokenClaimsContextKey.String()
	assert.Equal(t, `ContextKey("TokenClaims")`, keyString)
}

func TestGetClaims_Sucess(t *testing.T) {
	req := &http.Request{}
	claims := &TokenClaims{Roles: []Role{{"cp:employee:tech:"}}, DisplayName: "ltbesh"}
	ctx := context.WithValue(req.Context(), tokenClaimsContextKey, claims)
	req = req.WithContext(ctx)
	extractedClaims := GetClaims(req)
	assert.Equal(t, claims, extractedClaims)
}

func TestGetClaims_EmptyContext(t *testing.T) {
	req := &http.Request{}
	ctx := context.Background()
	req = req.WithContext(ctx)
	extractedClaims := GetClaims(req)
	if extractedClaims != nil {
		t.Errorf("Expected extracted claims to be nil")
	}
}
