#include <iostream>
#include <string>
#include <map>
#include <thread>       // For adding sleep
#include <chrono>       // For std::chrono::seconds
#include <ctime>
#include <cassert>      // For testing assertions
#include <sqlite3.h>    // Include SQLite library
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include "cpp-httplib-master/httplib.h"
#include "jwt-cpp/jwt.h" // Include JWT-CPP library for JWT generation

// Structure to store RSA key pair
struct RSAKey {
    std::string kid;
    std::string publicKey;
    std::string privateKey;
    std::time_t expiresAt;
};

// Map to store keys with their kid
std::map<std::string, RSAKey> keys;
RSAKey expiredKey; // Store an expired key for "expired" token generation

// SQLite Database
sqlite3 *db;

// Helper function for Base64 URL encoding
std::string bignumToBase64Url(const BIGNUM *bn) {
    int len = BN_num_bytes(bn);
    unsigned char *bin = new unsigned char[len];
    BN_bn2bin(bn, bin);

    std::string binaryData(reinterpret_cast<char*>(bin), len);
    std::string base64 = jwt::base::encode<jwt::alphabet::base64url>(binaryData);
    delete[] bin;
    return base64;
}

// Initialize SQLite Database and Create Table
bool initDatabase() {
    std::cout << "Attempting to initialize the database..." << std::endl;
    int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    std::cout << "Database opened successfully." << std::endl;

    const char *sql = R"(
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        );
    )";

    char *errMsg = nullptr;
    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error on table creation: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    std::cout << "Table 'keys' created or already exists." << std::endl;

    sqlite3_stmt *stmt;
    const char *checkTableSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='keys';";
    rc = sqlite3_prepare_v2(db, checkTableSQL, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error on checking table existence: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::cout << "Table 'keys' verified to exist in database." << std::endl;
    } else {
        std::cerr << "Table 'keys' does NOT exist in database after attempted creation." << std::endl;
    }
    sqlite3_finalize(stmt);

    return true;
}

// Generate RSA key pair and store it in the database, with an option to set as expired
void generateKeyPair(bool makeExpired = false) {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    BN_free(e);

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, rsa);

    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    char* pri_key = (char*)malloc(pri_len + 1);
    char* pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    std::string kid = "key_" + std::to_string(rand());
    std::time_t expiry = std::time(0) + (makeExpired ? -3600 : 3600);  // Set expiry to past if expired

    const char* insertSQL = "INSERT INTO keys (key, exp) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pri_key, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, expiry);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Error inserting key into database: " << sqlite3_errmsg(db) << std::endl;
    }
    sqlite3_finalize(stmt);

    free(pri_key);
    free(pub_key);
    BIO_free_all(pub);
    BIO_free_all(pri);
    RSA_free(rsa);
}

// JWKS handler (Handles GET /jwks)
void jwksHandler(const httplib::Request &req, httplib::Response &res) {
    std::time_t now = std::time(0);
    std::ostringstream jwks;
    jwks << "{ \"keys\": [";

    const char* selectSQL = "SELECT kid, key FROM keys WHERE exp > ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, now);

    bool first = true;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (!first) {
            jwks << ",";
        }
        first = false;

        std::string kid = std::to_string(sqlite3_column_int(stmt, 0));
        std::string publicKeyPem = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

        BIO *bio = BIO_new_mem_buf((void*)publicKeyPem.c_str(), -1);
        RSA *rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (rsa) {
            const BIGNUM *n, *e;
            RSA_get0_key(rsa, &n, &e, NULL);

            std::string n_str = bignumToBase64Url(n);
            std::string e_str = bignumToBase64Url(e);

            jwks << "{"
                 << "\"kty\": \"RSA\", "
                 << "\"kid\": \"" << kid << "\", "
                 << "\"n\": \"" << n_str << "\", "
                 << "\"e\": \"" << e_str << "\""
                 << "}";

            RSA_free(rsa);
        } else {
            std::cerr << "Error: Failed to parse RSA public key." << std::endl;
        }
    }

    sqlite3_finalize(stmt);

    jwks << "]}";
    res.set_content(jwks.str(), "application/json");
}

// Function to create a JWT
std::string createJWT(const RSAKey& key, bool isExpired) {
    auto token = jwt::create()
        .set_issuer("jwks_server")
        .set_type("JWT")
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(isExpired ? std::chrono::system_clock::now() - std::chrono::hours(1) : std::chrono::system_clock::now() + std::chrono::hours(1))
        .set_payload_claim("kid", jwt::claim(std::string(key.kid)))
        .sign(jwt::algorithm::rs256(key.publicKey, key.privateKey, "", ""));

    return token;
}

// Auth handler (Handles POST /auth)
void authHandler(const httplib::Request &req, httplib::Response &res) {
    bool expired = req.has_param("expired");

    const char* selectSQL = expired ?
        "SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1;" :
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1;";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, std::time(0));

    std::string jwt;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string kid = std::to_string(sqlite3_column_int(stmt, 0));
        std::string privateKey = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        std::time_t exp = sqlite3_column_int64(stmt, 2);

        RSAKey keyToUse = { kid, "", privateKey, exp };
        jwt = createJWT(keyToUse, expired);
    } else {
        res.status = 404;
        res.set_content("{\"error\":\"No appropriate key found\"}", "application/json");
        sqlite3_finalize(stmt);
        return;
    }
    sqlite3_finalize(stmt);

    res.set_content("{\"token\":\"" + jwt + "\"}", "application/json");
}

// Cleanup expired keys from the database
void cleanupExpiredKeys() {
    const char* deleteSQL = "DELETE FROM keys WHERE exp < ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, deleteSQL, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, std::time(0));

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Error deleting expired keys: " << sqlite3_errmsg(db) << std::endl;
    }
    sqlite3_finalize(stmt);
}

int main() {
    if (!initDatabase()) {
        std::cerr << "Failed to initialize the database." << std::endl;
        return 1;
    }

    generateKeyPair();
    generateKeyPair(true);

    httplib::Server svr;
    svr.Get("/jwks", jwksHandler);
    svr.Post("/auth", authHandler);

    std::cout << "Server is running on http://localhost:8080" << std::endl;

    svr.listen("0.0.0.0", 8080);
    sqlite3_close(db);

    return 0;
}
