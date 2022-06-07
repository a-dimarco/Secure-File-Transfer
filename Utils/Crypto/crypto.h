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
#include <openssl/rand.h>
#include <iostream>
#include "../Socket/connection_manager.h"

using namespace std;

class crypto {

public:

    int decrypt_message(unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *aad, int aad_len,
                        unsigned char *tag,
                        unsigned char *key,
                        unsigned char *iv,
                        unsigned char *plaintext);

    int encrypt_packet(unsigned char *plaintext, int plaintext_len,
                       unsigned char *aad, int aad_len,
                       unsigned char *key,
                       unsigned char *iv,
                       unsigned char *ciphertext,
                       unsigned char *tag);

    unsigned char *key_derivation(unsigned char *shared_secret, size_t size);

    EVP_PKEY *dh_params_gen();

    EVP_PKEY *dh_keygen();

    void serialize_dh_pubkey(EVP_PKEY *dh_key, char *pubkey);

    EVP_PKEY *deserialize_dh_pubkey(unsigned char *dh_key, long size);

    unsigned char *
    signn(unsigned char *clear_buf, long int clear_size, string prvkey_file_name, unsigned int *sgnt_size);

    unsigned char *dh_sharedkey(EVP_PKEY *my_key, EVP_PKEY *other_pubkey, size_t *size);

    bool
    verify_sign(unsigned char *sgnt_buf, long int sgnt_size, unsigned char *clear_buf, long int clear_size,
                EVP_PKEY *pk);

    bool verify_cert(X509 *cert);

    void create_random_iv(unsigned char *iv);

    void create_nonce(unsigned char *p);

};

#endif
