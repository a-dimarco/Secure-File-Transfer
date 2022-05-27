#ifndef SECURE_FILE_TRANSFER_CRYPTO_H
#define SECURE_FILE_TRANSFER_CRYPTO_H

#include <string>
#include <cstring>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
using namespace std;

class crypto {
public:
    int encrypt_message(const char* filename, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);//edo
                
    

    unsigned char *key_derivation(unsigned char *shared_secret, size_t size);//edo

    EVP_PKEY *dh_params_gen();//edo

    EVP_PKEY *dh_keygen(EVP_PKEY *dh_params);//genera coppia di chiavi dh

    unsigned char *serialize_dh_pubkey(EVP_PKEY *dh_key, long* size);//genera public key - edo
    EVP_PKEY* deserialize_dh_pubkey(unsigned char* dh_key, long size);

    unsigned char *dh_sharedkey(EVP_PKEY *my_key, EVP_PKEY *other_pubkey, size_t* size);//edo

    unsigned char *sign(unsigned char *msg, FILE private_key, char* psw);//lore

    bool verify_sign(unsigned char *signature, EVP_PKEY *key);//lore

    bool verify_cert(X509_STORE *cert);//lore

    EVP_PKEY *extract_pubkey(X509_STORE *cert);//lore

private:
    void handleError(char* s);//lore
};


#endif
