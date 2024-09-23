#include <iostream>
#include <string>
#include <map>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// Structure to store RSA key pair
struct RSAKey {
    std::string kid;
    std::string publicKey;
    std::string privateKey;
    std::time_t expiresAt;
};

// Map to store keys with their kid
std::map<std::string, RSAKey> keys;

// Generate RSA key pair and store it in the keys map
void generateKeyPair() {
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
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

    // Free memory
    free(pri_key);
    free(pub_key);
    BIO_free_all(pub);
    BIO_free_all(pri);
    RSA_free(rsa);
}

// Function to display available keys (JWKS endpoint simulation)
void displayJWKS() {
    std::time_t now = std::time(0);
    std::cout << "JWKS:" << std::endl;
    for (const auto& pair : keys) {
        const RSAKey& key = pair.second;
        if (key.expiresAt > now) {
            std::cout << "{ \"kid\": \"" << key.kid << "\", \"publicKey\": \"" << key.publicKey << "\" }" << std::endl;
        }
    }
}

int main() {
    // Simulate key generation and JWKS serving
    generateKeyPair();
    displayJWKS();

    return 0;
}

