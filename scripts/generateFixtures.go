/*
Use to re-generate the fixtures file:
$ go run scripts/generateFixtures.go | tee fixtures/fixtures.json

The aim is to be able to maintain hard-coded fixtures of signed tokens, but by experience it is a pain to do
because you have to find the private key, decode tokens, modify them, sign them again...
This script helps generating a new set of fixtures, but the fixtures themselves have to be committed.
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"encoding/json"

	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

type pseudoRole map[string]string

var validClaims = jwt.MapClaims{
	"iss":          "58ef76ab90bc",
	"sub":          "58ef76ab90bc",
	"display_name": "Alfred Bernard",
	"roles": []pseudoRole{{
		"name": "cp:client:rider:",
	}},
	"iat": 1453225473,
}

var expiredClaims = jwt.MapClaims{
	"iss":          "ab90bc58ef76",
	"sub":          "ab90bc58ef76",
	"display_name": "Carl De la Batte",
	"roles": []pseudoRole{{
		"name": "cp:client:rider:",
	}},
	"iat": 1453225473,
	"exp": 1485969700,
}

func main() {
	fixtures := generateFixtures()
	jsonFixtures, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(jsonFixtures))
}

func generateFixtures() map[string]interface{} {
	privateKey := generatePrivateKey()
	otherPrivateKey := generatePrivateKey()
	publicKeyPem, _ := generateKeyStrings(privateKey)
	fixtures := map[string]interface{}{}
	fixtures["RawRsaPublicKey"] = publicKeyPem
	allClaims := map[string]interface{}{}
	fixtures["Claims"] = allClaims
	addTokenAndClaims(fixtures, allClaims, "TokenValidWithRiderRole", &validClaims, privateKey, true)
	addTokenAndClaims(fixtures, allClaims, "TokenExpired", &expiredClaims, privateKey, true)
	addTokenAndClaims(fixtures, allClaims, "TokenWithInvalidAlgorithm", &validClaims, privateKey, false)
	addTokenAndClaims(fixtures, allClaims, "TokenWithInvalidSignature", &validClaims, otherPrivateKey, true)
	return fixtures
}

func addTokenAndClaims(
	fixtures map[string]interface{},
	allClaims map[string]interface{},
	name string, claims *jwt.MapClaims,
	privateKey *rsa.PrivateKey,
	useRS256 bool,
) {
	tokenString := generateToken(claims, privateKey, useRS256)
	fixtures[name] = tokenString
	allClaims[name] = claims
}

func generatePrivateKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func generateKeyStrings(privateKey *rsa.PrivateKey) (string, string) {
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	privateKeyPem := string(pem.EncodeToMemory(&privateKeyBlock))

	publicKey := privateKey.PublicKey
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}

	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	return publicKeyPem, privateKeyPem
}

func getSigningMethodAndPrivateKey(useRS256 bool, privateKey *rsa.PrivateKey) (jwt.SigningMethod, interface{}) {
	if useRS256 {
		return jwt.SigningMethodRS256, privateKey
	}
	return jwt.SigningMethodHS256, []byte("some-fake-key")
}

func generateToken(claims *jwt.MapClaims, privateKey *rsa.PrivateKey, useRS256 bool) string {
	signingMethod, actualKey := getSigningMethodAndPrivateKey(useRS256, privateKey)
	jwtToken := jwt.NewWithClaims(signingMethod, claims)
	tokenString, err := jwtToken.SignedString(actualKey)
	if err != nil {
		panic(err)
	}
	return tokenString
}
