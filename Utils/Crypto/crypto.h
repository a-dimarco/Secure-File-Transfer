#ifndef SECURE_FILE_TRANSFER_CRYPTO_H
#define SECURE_FILE_TRANSFER_CRYPTO_H
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

using namespace std;

class crypto {
public:
    unsigned char* encrypt_message();
    unsigned char* key_derivation(unsigned char *shared_secret);
    EVP_PKEY* dh_params_gen();
    unsigned char* dh_pubkey(EVP_PKEY* dh_params);
    unsigned char* dh_sharedkey(EVP_PKEY* dh_params, EVP_PKEY* public_key, EVP_PKEY* private_key);
    unsigned char* sign(unsigned char* msg, file private_key, string psw);
    bool verify_sign(unsigned char* signature, EVP_PKEY* key);
    bool verify_cert(X509_STORE* cert);
    EVP_PKEY* extract_pubkey(X509_STORE* cert);

private:
    void handleError(string s);
};


#endif
