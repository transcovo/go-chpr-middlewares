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
	"strings"

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
	RawRsaPublicListKeys      string
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
GetRsaPublicKeysList returns the list of rsa public keys to verify the following tokens
*/
func GetRsaPublicKeysList() []*rsa.PublicKey {
	rawPublicKeys := strings.Split(Fixtures.RawRsaPublicListKeys, ";\n")
	publicKey1, err := jwt.ParseRSAPublicKeyFromPEM([]byte(rawPublicKeys[0]))
	if err != nil {
		panic(err)
	}
	publicKey2, err := jwt.ParseRSAPublicKeyFromPEM([]byte(rawPublicKeys[1]))
	if err != nil {
		panic(err)
	}
	publicKey3, err := jwt.ParseRSAPublicKeyFromPEM([]byte(rawPublicKeys[2]))
	if err != nil {
		panic(err)
	}
	return []*rsa.PublicKey{publicKey1, publicKey2, publicKey3}
}

/*
Fake200Handler is a dead-simple http.HandlerFunc returning a 200 OK
*/
func Fake200Handler(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(http.StatusOK)
}
