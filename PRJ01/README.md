# jwks-server-cpp
JWKS Server in C++ with JWT Authentication
Project Overview
This project implements a basic JSON Web Key Set (JWKS) server in C++ using OpenSSL for RSA key generation and jwt-cpp for creating and signing JSON Web Tokens (JWT). The server includes two main RESTful endpoints:

/jwks: Serves the public keys in JWKS format, which can be used to verify JWTs.
/auth: Issues JWTs signed with RSA keys, with an option to use an expired key.
Features
RSA Key Pair Generation (Public and Private keys).
JWKS endpoint (/jwks) that serves active public keys for JWT verification.
JWT issuance via the /auth endpoint with support for signing tokens with expired keys.
JWTs include kid (key ID) in their headers for key identification.

use g++ -std=c++11 -o server server_new.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto