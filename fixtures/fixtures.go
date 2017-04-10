/*
To re-generate the fixtures file, you can run
$ go run scripts/generateFixtures.go | tee fixtures/fixtures.json
*/

package fixtures

import (
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

/*
FixtureContent defines all fixtures in fixtures.json
*/
type FixtureContent struct {
	RawRsaPublicKey           string
	TokenValidWithRiderRole   string
	TokenExpired              string
	TokenWithInvalidAlgorithm string
	TokenWithInvalidSignature string
}

/*
Fixtures parsed from fixtures.json
*/
var Fixtures = func() FixtureContent {
	content, err := ioutil.ReadFile("fixtures/fixtures.json")
	if err != nil {
		panic(err)
	}
	fixtures := &FixtureContent{}
	json.Unmarshal(content, fixtures)
	return *fixtures
}()

/*
GetRsaPublicKey returns the rsa public key to verify the following tokens
*/
func GetRsaPublicKey() *rsa.PublicKey {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(Fixtures.RawRsaPublicKey))
	if err != nil {
		panic(err)
	}
	return publicKey
}

/*
Fake200Handler is a dead-simple http.HandlerFunc returning a 200 OK
*/
func Fake200Handler(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}
