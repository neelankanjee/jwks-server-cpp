#include <iostream>
#include <string>
#include <map>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
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

// Generate RSA key pair and store it in the keys map
void generateKeyPair() {
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

    // Set expiry time to 1 hour from now
    std::time_t expiry = std::time(0) + 3600;

    // Store the keys
    keys[kid] = {kid, std::string(pub_key), std::string(pri_key), expiry};

    // Save the expired key for testing the "expired" token functionality
    if (expiredKey.kid.empty()) {
        expiredKey = {kid, std::string(pub_key), std::string(pri_key), std::time(0) - 3600}; // Expired key
    }

    // Free memory
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
    for (const auto& pair : keys) {
        const RSAKey& key = pair.second;
        if (key.expiresAt > now) {
            jwks << "{ \"kid\": \"" << key.kid << "\", \"publicKey\": \"" << key.publicKey << "\" },";
        }
    }
    std::string jwks_str = jwks.str();
    if (jwks_str.back() == ',') {
        jwks_str.pop_back(); // Remove the trailing comma
    }
    jwks_str += "]}";
    res.set_content(jwks_str, "application/json");
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
    RSAKey keyToUse = expired ? expiredKey : keys.begin()->second; // Use the expired key if 'expired' query parameter is present

    // Generate a JWT
    std::string jwt = createJWT(keyToUse, expired);

    // Respond with the generated JWT
    res.set_content("{\"token\":\"" + jwt + "\"}", "application/json");
}

 {
    // Simulate key generation
    generateKeyPair();

    httplib::Server svr;

    // Set up the JWKS endpoint
    svr.Get("/jwks", jwksHandler);

    // Set up the auth endpoint
    svr.Post("/auth", authHandler);

    // Listen on port 8080
    std::cout << "Server is running on http://localhost:8080" << std::endl;
    svr.listen("0.0.0.0", 8080);

    return 0;
}