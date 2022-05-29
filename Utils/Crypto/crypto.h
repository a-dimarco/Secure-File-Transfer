#ifndef SECURE_FILE_TRANSFER_CRYPTO_H
#define SECURE_FILE_TRANSFER_CRYPTO_H
#pragma once
#include <string>
#include <cstring>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include<iostream>

using namespace std;

class crypto {
public:
    int decrypt_message(unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *aad, int aad_len,
                        unsigned char *tag,
                        unsigned char *key,
                        unsigned char *iv, int iv_len,
                        unsigned char *plaintext);
    int encrypt_message(FILE* file, int plaintext_len,
                        unsigned char *aad, int aad_len,
                        unsigned char *key,
                        unsigned char *iv, int iv_len,
                        unsigned char *ciphertext,
                        unsigned char *tag);//edo

    int encrypt_packet(unsigned char *plaintext, int plaintext_len,
                       unsigned char *aad, int aad_len,
                       unsigned char *key,
                       unsigned char *iv, int iv_len,
                       unsigned char *ciphertext,
                       unsigned char *tag);

    unsigned char *key_derivation(unsigned char *shared_secret, size_t size);//edo

    EVP_PKEY *dh_params_gen();//edo

    EVP_PKEY *dh_keygen(EVP_PKEY *dh_params);//genera coppia di chiavi dh

    unsigned char *serialize_dh_pubkey(EVP_PKEY *dh_key, long *size);//genera public key - edo
    EVP_PKEY *deserialize_dh_pubkey(unsigned char *dh_key, long size);

    unsigned char *dh_sharedkey(EVP_PKEY *my_key, EVP_PKEY *other_pubkey, size_t *size);//edo

    unsigned char *sign(unsigned char *clear_buf, long int clear_size, string prvkey_file_name, char *psw);//lore

    bool
    verify_sign(unsigned char *sgnt_buf, int *key, long int sgnt_size, unsigned char *clear_buf, long int clear_size,
                X509 *cert);//lore

    bool verify_cert(X509 *cert);//lore

    unsigned char *get_key();

    unsigned char *create_random_iv();

    unsigned char *create_nonce();

    //EVP_PKEY *extract_pubkey(X509_STORE *cert);//lore

private:
    void handleError(char *s);//lore
    unsigned char *shared_key; //free it when the session is finished
};


#endif
