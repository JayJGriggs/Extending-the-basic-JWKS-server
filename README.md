This project builds on the last JWKS server from Project 1 by adding the SQLite database to store RSA private keys instead of keeping them in memory.
What's new:
Private keys are now saved to a SQLite database file called totally_not_my_privateKeys.db
Keys are stored in PKCS1 PEM format and loaded from the database on each request
The /auth endpoint reads a valid or expired key from the database, depending on the query parameter
The /.well-known/jwks.json endpoint reads all non-expired keys from the database
All database queries use parameterized statements to prevent SQL injection
Test coverage is above the 80% requirement 
