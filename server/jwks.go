package server

import (
	"encoding/base64"
	"math/big"
)

// JWKS is the JSON response object: { "keys": [ ... ] }
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents ONE RSA public key in JWKS format.
type JWK struct {
	KTY string `json:"kty"` // Key Type (RSA)
	Use string `json:"use"` // sig
	ALG string `json:"alg"` // RS256
	KID string `json:"kid"` // key id
	N   string `json:"n"`   // modulus
	E   string `json:"e"`   // exponent
}

// rsaPublicToJWK converts RSA public numbers (N and E) into JWKS fields.
func rsaPublicToJWK(kid string, n *big.Int, e int) JWK {
	// n = modulus (big number)
	nB64 := base64.RawURLEncoding.EncodeToString(n.Bytes())

	// e = exponent (small number like 65537)
	eBig := big.NewInt(int64(e))
	eB64 := base64.RawURLEncoding.EncodeToString(eBig.Bytes())

	return JWK{
		KTY: "RSA",
		Use: "sig",
		ALG: "RS256",
		KID: kid,
		N:   nB64,
		E:   eB64,
	}
}
