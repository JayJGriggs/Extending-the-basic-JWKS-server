package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Header part of a JWT. We MUST include kid.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	KID string `json:"kid"`
}

// Claims part of a JWT. We keep it simple.
type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// IssueJWT creates a JWT signed with RS256.
// If expired=true, token exp is in the past (expired token).
func IssueJWT(key KeyPair, expired bool) (string, error) {
	now := time.Now().UTC()

	header := jwtHeader{
		Alg: "RS256",
		Typ: "JWT",
		KID: key.KID,
	}

	// Normal tokens expire in 5 minutes.
	// Expired tokens expire 5 minutes ago.
	exp := now.Add(5 * time.Minute).Unix()
	if expired {
		exp = now.Add(-5 * time.Minute).Unix()
	}

	claims := jwtClaims{
		Sub: "user",
		Iat: now.Unix(),
		Exp: exp,
	}

	// Convert header and claims into JSON bytes
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Base64URL encode them (JWT standard)
	enc := base64.RawURLEncoding
	hPart := enc.EncodeToString(headerJSON)
	cPart := enc.EncodeToString(claimsJSON)

	// This is what we sign
	signingInput := hPart + "." + cPart

	// Sign using RSA + SHA-256 (RS256)
	sigBytes, err := signRS256(key.Priv, signingInput)
	if err != nil {
		return "", err
	}

	// Final token = header.claims.signature
	return signingInput + "." + enc.EncodeToString(sigBytes), nil
}

// signRS256 signs the input using RSA PKCS#1 v1.5 with SHA-256.
func signRS256(priv *rsa.PrivateKey, input string) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key is nil")
	}
	hash := sha256.Sum256([]byte(input))
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
}

// ParseJWTParts is a helper for tests: split token into 3 parts.
func ParseJWTParts(token string) (headerB64, claimsB64, sigB64 string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
