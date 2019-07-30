package middleware

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/transcovo/go-chpr-middlewares/fixtures"
)

func TestMiddleware_OneKeyUnauthorized(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{}, true, false)
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, &http.Request{})
	res := recorder.Result()
	assert.Equal(t, 401, res.StatusCode)
	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "Unauthorized\n", string(body))
}

func TestMiddleware_ListKeysUnauthorized(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicListKeys, &logrus.Logger{}, true, false)
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, &http.Request{})
	res := recorder.Result()
	assert.Equal(t, 401, res.StatusCode)
	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "Unauthorized\n", string(body))
}

func TestMiddleware_Unathorized_WhenClaimsCannotBeExtract_WithoutVerifyToken(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicListKeys, &logrus.Logger{}, false, false)
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	headers := http.Header{"Authorization": {"Bearer token"}}
	wrappedHandler(recorder, &http.Request{Header: headers})

	res := recorder.Result()
	assert.Equal(t, 401, res.StatusCode)
	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "Unauthorized\n", string(body))
}

func TestMiddleware_ValidToken(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{}, true, false)
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	headers := http.Header{"Authorization": {"Bearer " + fixtures.Fixtures.TokenValidWithRiderRole}}
	wrappedHandler(recorder, &http.Request{Header: headers})
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)
}

func TestMiddleware_ListKeysValidTokenWithThirdKey(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicListKeys, &logrus.Logger{}, true, false)
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)

	recorder := httptest.NewRecorder()
	headers := http.Header{"Authorization": {"Bearer " + fixtures.Fixtures.TokenValidWithRiderRole}}
	wrappedHandler(recorder, &http.Request{Header: headers})
	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)
}

func TestMiddleWare_StoreInformationInRequestcontext(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{}, true, false)
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

func TestMiddleWare_StoreInformationInRequestcontext_WithVerifyToken_WithExpiredToken_IgnoreExpiration(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{}, true, true)
	modifiedRequest := &http.Request{}
	fakeHandler := func(res http.ResponseWriter, req *http.Request) {
		modifiedRequest = req
	}

	wrappedHandler := jwtMiddleware(fakeHandler)
	headers := http.Header{"Authorization": {"Bearer " + fixtures.Fixtures.TokenExpired}}
	initialRequest := &http.Request{Header: headers}
	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, initialRequest)

	storedClaims := modifiedRequest.Context().Value(tokenClaimsContextKey).(*TokenClaims)
	assert.Equal(t, []Role{{Name: "cp:client:rider:"}}, storedClaims.Roles)
	assert.Equal(t, "Carl De la Batte", storedClaims.DisplayName)
}

func TestMiddleWare_StoreInformationInRequestcontext_WithoutVerifyToken_WithExpiredToken(t *testing.T) {
	jwtMiddleware := JwtAuthenticationMiddleware("", &logrus.Logger{}, false, false)
	modifiedRequest := &http.Request{}
	fakeHandler := func(res http.ResponseWriter, req *http.Request) {
		modifiedRequest = req
	}

	wrappedHandler := jwtMiddleware(fakeHandler)
	headers := http.Header{"Authorization": {"Bearer " + fixtures.Fixtures.TokenExpired}}
	initialRequest := &http.Request{Header: headers}
	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, initialRequest)

	storedClaims := modifiedRequest.Context().Value(tokenClaimsContextKey).(*TokenClaims)
	assert.Equal(t, []Role{{Name: "cp:client:rider:"}}, storedClaims.Roles)
	assert.Equal(t, "Carl De la Batte", storedClaims.DisplayName)
}

func TestMiddleware_IgnoredAuthenticationForDevelopmentMode(t *testing.T) {
	os.Setenv("IGNORE_AUTH", "true")
	defer os.Setenv("IGNORE_AUTH", "")

	// no public key is required in this case
	jwtMiddleware := JwtAuthenticationMiddleware("", &logrus.Logger{}, true, false)
	wrappedHandler := jwtMiddleware(fixtures.Fake200Handler)
	recorder := httptest.NewRecorder()
	wrappedHandler(recorder, &http.Request{})

	res := recorder.Result()
	assert.Equal(t, 200, res.StatusCode)

	body, _ := ioutil.ReadAll(res.Body)
	assert.Equal(t, "", string(body))
}

func TestParsePublicKeysList_ValidKey(t *testing.T) {
	parsed := parsePublicKeysList(fixtures.Fixtures.RawRsaPublicKey, &logrus.Logger{})
	assert.Len(t, parsed, 1)
	assert.Equal(t, fixtures.GetRsaPublicKey(), parsed[0])
}

func TestParsePublicKeysList_ValidListKeys(t *testing.T) {
	parsed := parsePublicKeysList(fixtures.Fixtures.RawRsaPublicListKeys, &logrus.Logger{})
	assert.Len(t, parsed, 3)
	assert.Equal(t, fixtures.GetRsaPublicKeysList(), parsed)
}

func TestParsePublicKeysList_InvalidKey(t *testing.T) {
	parseInvalidKey := func() {
		parsePublicKeysList("not a key !", &logrus.Logger{})
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

func TestGetParsedToken_InvalidAlgorithm_WithoutVerifyToken(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenWithInvalidAlgorithm)
	rawPublicKey := fixtures.Fixtures.RawRsaPublicKey
	parsed, err := getParsedToken(token, rawPublicKey, false, false, &logrus.Logger{})
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
	assert.Equal(t,
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaXNwbGF5X25hbWUiOiJBbGZyZWQgQmVybmFyZCIsImlhdCI6MT" +
		"Q1MzIyNTQ3MywiaXNzIjoiNThlZjc2YWI5MGJjMTIzNDEyMzQxMjM0Iiwicm9sZXMiOlt7Im5hbWUiOiJ" +
		"jcDpjbGllbnQ6cmlkZXI6In1dLCJzdWIiOiI1OGVmNzZhYjkwYmMxMjM0MTIzNDEyMzQifQ.s2p067HnNQAaHLZo9MFwr28zni_8gITZPB5zaBuPKHQ",
		parsed.Raw)
}

func TestGetParsedToken_ExpiredToken_WithVerifyToken_WithoutIgnoreExpiration(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenExpired)
	rawPublicKey := fixtures.Fixtures.RawRsaPublicKey
	parsed, err := getParsedToken(token, rawPublicKey, true, false, &logrus.Logger{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired by")
	assert.Nil(t, parsed)
}

func TestGetParsedToken_ExpiredToken_WithVerifyToken_WithIgnoreExpiration(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenExpired)
	rawPublicKey := fixtures.Fixtures.RawRsaPublicKey
	parsed, err := getParsedToken(token, rawPublicKey, true, true, &logrus.Logger{})
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestValidateToken_NoRsaKey(t *testing.T) {
	validToken := rawToken(fixtures.Fixtures.TokenValidWithRiderRole)
	parsed, err := validateToken(validToken, nil, true, false)
	assert.EqualError(t, err, "missing public key")
	assert.Nil(t, parsed)
}

func TestValidateToken_Empty(t *testing.T) {
	parsed, err := validateToken(emptyToken, fixtures.GetRsaPublicKey(), true, false)
	assert.EqualError(t, err, "token contains an invalid number of segments")
	assert.Nil(t, parsed)
}

func TestValidateToken_InvalidAlgorithm(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenWithInvalidAlgorithm)
	parsed, err := validateToken(token, fixtures.GetRsaPublicKey(), true, true)
	assert.EqualError(t, err, "unexpected signing method: HS256")
	assert.Nil(t, parsed)
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenWithInvalidSignature)
	parsed, err := validateToken(token, fixtures.GetRsaPublicKey(), true, false)
	assert.EqualError(t, err, "crypto/rsa: verification error")
	assert.Nil(t, parsed)
}

func TestValidateToken_Expired(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenExpired)
	parsed, err := validateToken(token, fixtures.GetRsaPublicKey(), true, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired by")
	assert.Nil(t, parsed)
}

func TestValidateToken_Expired_IgnoreExpiration(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenExpired)
	parsed, err := validateToken(token, fixtures.GetRsaPublicKey(), true, true)
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestValidateToken_ValidToken(t *testing.T) {
	token := rawToken(fixtures.Fixtures.TokenValidWithRiderRole)
	parsed, err := validateToken(token, fixtures.GetRsaPublicKey(), true, false)
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
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
