package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"time"
)

// KeyPair is one RSA private key plus metadata.
type KeyPair struct {
	KID       string        // key id used in JWT header and JWKS
	ExpiresAt time.Time     // when this key is considered expired
	Priv      *rsa.PrivateKey // private key used to SIGN JWTs
}

// KeyStore holds our two keys for this assignment:
// - Active key: not expired, used for normal /auth
// - Expired key: expired, used when /auth?expired is requested
type KeyStore struct {
	Active  KeyPair
	Expired KeyPair
}

// NewKeyStore generates 2 RSA keys on startup.
// This is okay for an educational mock server.
func NewKeyStore() (*KeyStore, error) {
	activePriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	expiredPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	return &KeyStore{
		Active: KeyPair{
			KID:       newKID(),
			ExpiresAt: now.Add(24 * time.Hour), // expires in the future (active)
			Priv:      activePriv,
		},
		Expired: KeyPair{
			KID:       newKID(),
			ExpiresAt: now.Add(-24 * time.Hour), // expired in the past
			Priv:      expiredPriv,
		},
	}, nil
}

// newKID makes a short random string for "kid".
func newKID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // ignoring error here is OK for a simple assignment
	return base64.RawURLEncoding.EncodeToString(b)
}
