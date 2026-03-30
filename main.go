package main

import (
	"log"
	"net/http"

	"jwks-server/server"
)

func main() {
	// Open (or create) the SQLite DB file.
	db, err := server.OpenDB()
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Seed the DB with one valid key and one expired key.
	if err := server.SeedKeys(db); err != nil {
		log.Fatalf("failed to seed keys: %v", err)
	}

	// Register HTTP routes, passing the DB connection.
	mux := http.NewServeMux()
	server.RegisterRoutes(mux, db)

	log.Println("Server running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("server crashed: %v", err)
	}
}
