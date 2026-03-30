package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"

	// SQLite driver (CGO-based, most compatible)
	_ "github.com/mattn/go-sqlite3"
)

const dbFile = "totally_not_my_privateKeys.db"

// OpenDB opens (or creates) the SQLite DB and initialises the schema.
func OpenDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}

	// Create the table exactly as specified in the rubric.
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

// SeedKeys generates two RSA keys and stores them in the DB:
//   - one valid key  (exp = now + 1 hour)
//   - one expired key (exp = now - 1 hour)
//
// Called once at start-up.
func SeedKeys(db *sql.DB) error {
	now := time.Now().UTC()

	// Active key — expires in 1 hour
	if err := generateAndStoreKey(db, now.Add(time.Hour)); err != nil {
		return err
	}
	// Expired key — expired 1 hour ago
	if err := generateAndStoreKey(db, now.Add(-time.Hour)); err != nil {
		return err
	}
	return nil
}

// generateAndStoreKey creates a 2048-bit RSA key and stores it as a PKCS1 PEM blob.
func generateAndStoreKey(db *sql.DB, expiresAt time.Time) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Encode to PKCS1 PEM so we can store it as text/BLOB in SQLite.
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	// Use a parameterised query — no string interpolation, no SQL injection risk.
	_, err = db.Exec(
		`INSERT INTO keys(key, exp) VALUES (?, ?)`,
		pemBytes,
		expiresAt.Unix(),
	)
	return err
}

// DBKeyRow is a row read back from the DB.
type DBKeyRow struct {
	KID  int64          // auto-incremented integer kid
	Priv *rsa.PrivateKey
	Exp  time.Time
}

// GetValidKey fetches one unexpired key from the DB.
func GetValidKey(db *sql.DB) (*DBKeyRow, error) {
	now := time.Now().UTC().Unix()
	// Parameterised WHERE clause — safe from injection.
	row := db.QueryRow(
		`SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1`,
		now,
	)
	return scanKeyRow(row)
}

// GetExpiredKey fetches one expired key from the DB.
func GetExpiredKey(db *sql.DB) (*DBKeyRow, error) {
	now := time.Now().UTC().Unix()
	row := db.QueryRow(
		`SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1`,
		now,
	)
	return scanKeyRow(row)
}

// GetAllValidKeys returns every unexpired key (used to build JWKS response).
func GetAllValidKeys(db *sql.DB) ([]*DBKeyRow, error) {
	now := time.Now().UTC().Unix()
	rows, err := db.Query(
		`SELECT kid, key, exp FROM keys WHERE exp > ?`,
		now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*DBKeyRow
	for rows.Next() {
		r, err := scanKeyRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// scanKeyRow is a helper that works for both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanKeyRow(s scanner) (*DBKeyRow, error) {
	var kid int64
	var keyPEM []byte
	var expUnix int64

	if err := s.Scan(&kid, &keyPEM, &expUnix); err != nil {
		return nil, err
	}

	// Decode PEM → RSA private key
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &DBKeyRow{
		KID:  kid,
		Priv: priv,
		Exp:  time.Unix(expUnix, 0).UTC(),
	}, nil
}
