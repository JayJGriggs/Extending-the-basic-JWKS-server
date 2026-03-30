package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// RegisterRoutes wires up the two required endpoints.
// The *sql.DB is injected so handlers can query the database.
func RegisterRoutes(mux *http.ServeMux, db *sql.DB) {
	// GET /.well-known/jwks.json — return all non-expired public keys
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		handleJWKS(w, db)
	})

	// POST /auth — issue a JWT (expired or valid depending on query param)
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		handleAuth(w, r, db)
	})
}

// handleJWKS reads all unexpired keys from the DB and returns them as JWKS JSON.
func handleJWKS(w http.ResponseWriter, db *sql.DB) {
	keys, err := GetAllValidKeys(db)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	resp := JWKS{Keys: []JWK{}}
	for _, k := range keys {
		pub := k.Priv.PublicKey
		resp.Keys = append(resp.Keys, rsaPublicToJWK(kidStr(k.KID), pub.N, pub.E))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleAuth issues a JWT.
//   - POST /auth         → valid JWT signed with an unexpired key
//   - POST /auth?expired → JWT with exp in the past, signed with an expired key
//
// The gradebot may send HTTP Basic Auth or JSON body credentials.
// We mock successful auth and just return a token.
func handleAuth(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	_, expiredMode := r.URL.Query()["expired"]

	var row *DBKeyRow
	var err error

	if expiredMode {
		row, err = GetExpiredKey(db)
	} else {
		row, err = GetValidKey(db)
	}
	if err != nil {
		http.Error(w, "no key available", http.StatusInternalServerError)
		return
	}

	kp := KeyPair{
		KID:       kidStr(row.KID),
		ExpiresAt: row.Exp,
		Priv:      row.Priv,
	}

	token, err := IssueJWT(kp, expiredMode)
	if err != nil {
		http.Error(w, "could not create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// kidStr converts the DB integer primary key to a string kid for JWT/JWKS.
func kidStr(kid int64) string {
	return fmt.Sprintf("%s", strconv.FormatInt(kid, 10))
}

// jwksFromKeyStore builds a JWKS directly from an in-memory KeyStore.
// Used internally by tests that need a KeyStore-backed response.
func jwksFromKeyStore(ks *KeyStore) JWKS {
	now := time.Now().UTC()
	resp := JWKS{Keys: []JWK{}}
	if now.Before(ks.Active.ExpiresAt) {
		pub := ks.Active.Priv.PublicKey
		resp.Keys = append(resp.Keys, rsaPublicToJWK(ks.Active.KID, pub.N, pub.E))
	}
	if now.Before(ks.Expired.ExpiresAt) {
		pub := ks.Expired.Priv.PublicKey
		resp.Keys = append(resp.Keys, rsaPublicToJWK(ks.Expired.KID, pub.N, pub.E))
	}
	return resp
}
