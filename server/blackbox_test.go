package server

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestDB creates a fresh in-memory SQLite DB, seeds it, and returns it.
// Using "file::memory:?cache=shared" gives us an in-memory DB per test.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file::memory:?cache=shared&mode=memory")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	// Unique schema per connection
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	if err := SeedKeys(db); err != nil {
		t.Fatalf("seed keys: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestJWKSOnlyReturnsUnexpiredKeys(t *testing.T) {
	db := newTestDB(t)

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}

	// SeedKeys adds 1 valid + 1 expired; only valid should appear.
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
}

func TestAuthNormalGivesUnexpiredToken(t *testing.T) {
	db := newTestDB(t)

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := http.Post(ts.URL+"/auth", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /auth: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var out map[string]string
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	token := out["token"]
	if token == "" {
		t.Fatalf("missing token in response")
	}

	_, cb64, _, ok := ParseJWTParts(token)
	if !ok {
		t.Fatalf("token not 3 parts")
	}

	cjson, err := base64.RawURLEncoding.DecodeString(cb64)
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	_ = json.Unmarshal(cjson, &claims)

	expF, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp missing in claims")
	}
	if int64(expF) <= time.Now().UTC().Unix() {
		t.Fatalf("expected valid (future) exp, got %v", int64(expF))
	}
}

func TestAuthExpiredQueryGivesExpiredToken(t *testing.T) {
	db := newTestDB(t)

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := http.Post(ts.URL+"/auth?expired=true", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /auth?expired=true: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var out map[string]string
	_ = json.NewDecoder(res.Body).Decode(&out)
	token := out["token"]

	_, cb64, _, ok := ParseJWTParts(token)
	if !ok {
		t.Fatalf("token not 3 parts")
	}

	cjson, _ := base64.RawURLEncoding.DecodeString(cb64)
	var claims map[string]any
	_ = json.Unmarshal(cjson, &claims)

	expF, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp missing")
	}
	if int64(expF) >= time.Now().UTC().Unix() {
		t.Fatalf("expected expired token, exp=%d is in the future", int64(expF))
	}
}

func TestWrongMethodsReturn405(t *testing.T) {
	db := newTestDB(t)

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res1, _ := http.Get(ts.URL + "/auth")
	res1.Body.Close()
	if res1.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET /auth, got %d", res1.StatusCode)
	}

	res2, _ := http.Post(ts.URL+"/.well-known/jwks.json", "application/json", nil)
	res2.Body.Close()
	if res2.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST jwks, got %d", res2.StatusCode)
	}
}

func TestJWKSFields(t *testing.T) {
	db := newTestDB(t)

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, _ := http.Get(ts.URL + "/.well-known/jwks.json")
	defer res.Body.Close()

	var jwks JWKS
	_ = json.NewDecoder(res.Body).Decode(&jwks)

	k := jwks.Keys[0]
	if k.KTY != "RSA" {
		t.Errorf("expected kty RSA, got %s", k.KTY)
	}
	if k.ALG != "RS256" {
		t.Errorf("expected alg RS256, got %s", k.ALG)
	}
	if k.Use != "sig" {
		t.Errorf("expected use sig, got %s", k.Use)
	}
	if k.N == "" || k.E == "" {
		t.Errorf("expected N and E to be set")
	}
}

func TestSeedKeysIdempotent(t *testing.T) {
	db := newTestDB(t)
	// Seed a second time — we should now have 4 rows (2 valid + 2 expired).
	if err := SeedKeys(db); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	keys, err := GetAllValidKeys(db)
	if err != nil {
		t.Fatalf("get valid keys: %v", err)
	}
	if len(keys) < 1 {
		t.Fatalf("expected at least 1 valid key after double seed")
	}
}

func TestGetExpiredKeyReturnsKey(t *testing.T) {
	db := newTestDB(t)
	row, err := GetExpiredKey(db)
	if err != nil {
		t.Fatalf("GetExpiredKey: %v", err)
	}
	if row == nil {
		t.Fatal("expected a row, got nil")
	}
	if row.Exp.After(time.Now().UTC()) {
		t.Fatalf("expected expired key, got exp=%v", row.Exp)
	}
}

func TestTokenHasKIDInHeader(t *testing.T) {
	db := newTestDB(t)

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, _ := http.Post(ts.URL+"/auth", "application/json", nil)
	defer res.Body.Close()

	var out map[string]string
	_ = json.NewDecoder(res.Body).Decode(&out)

	hb64, _, _, ok := ParseJWTParts(out["token"])
	if !ok {
		t.Fatal("bad token")
	}
	hjson, _ := base64.RawURLEncoding.DecodeString(hb64)
	var hdr map[string]any
	_ = json.Unmarshal(hjson, &hdr)

	if hdr["kid"] == nil || hdr["kid"] == "" {
		t.Fatalf("expected kid in JWT header, got: %v", hdr)
	}
}

// --- Additional tests to boost coverage above 80% ---

func TestOpenDB(t *testing.T) {
	// Test that OpenDB creates the file and table correctly.
	// Use a temp file path.
	t.TempDir()
	db, err := OpenDB()
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	// Verify the keys table exists by inserting and reading.
	if err := SeedKeys(db); err != nil {
		t.Fatalf("seed after OpenDB: %v", err)
	}
}

func TestNewKeyStore(t *testing.T) {
	ks, err := NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	if ks.Active.KID == "" || ks.Expired.KID == "" {
		t.Fatal("expected non-empty KIDs")
	}
	if ks.Active.Priv == nil || ks.Expired.Priv == nil {
		t.Fatal("expected non-nil private keys")
	}
	if ks.Active.ExpiresAt.Before(time.Now().UTC()) {
		t.Fatal("active key should not be expired")
	}
	if ks.Expired.ExpiresAt.After(time.Now().UTC()) {
		t.Fatal("expired key should be in the past")
	}
}

func TestJwksFromKeyStore(t *testing.T) {
	ks, _ := NewKeyStore()
	jwks := jwksFromKeyStore(ks)
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 unexpired key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KID != ks.Active.KID {
		t.Fatalf("wrong kid")
	}
}

func TestIssueJWTExpiredFlag(t *testing.T) {
	ks, _ := NewKeyStore()
	token, err := IssueJWT(ks.Expired, true)
	if err != nil {
		t.Fatalf("IssueJWT expired: %v", err)
	}
	_, cb64, _, ok := ParseJWTParts(token)
	if !ok {
		t.Fatal("bad token")
	}
	cjson, _ := base64.RawURLEncoding.DecodeString(cb64)
	var claims map[string]any
	_ = json.Unmarshal(cjson, &claims)
	expF := claims["exp"].(float64)
	if int64(expF) >= time.Now().UTC().Unix() {
		t.Fatal("expected expired exp")
	}
}

func TestParseJWTPartsBadInput(t *testing.T) {
	_, _, _, ok := ParseJWTParts("not.a.valid.jwt.with.too.many.parts")
	if ok {
		t.Fatal("expected false for malformed token")
	}
	_, _, _, ok2 := ParseJWTParts("onlytwoparts.here")
	if ok2 {
		t.Fatal("expected false for 2-part token")
	}
}

func TestHandleAuthNoKeyAvailable(t *testing.T) {
	// DB with NO rows — handler should return 500.
	db, err := sql.Open("sqlite3", "file::memory:?cache=shared&mode=memory&_db=empty")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	// No SeedKeys — table is empty.

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, _ := http.Post(ts.URL+"/auth", "application/json", nil)
	res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", res.StatusCode)
	}
}
