#ifndef SECURE_FILE_TRANSFER_CRYPTO_H
#define SECURE_FILE_TRANSFER_CRYPTO_H
#include <tuple>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <iostream>
#include <string>
#include <stdio.h>
#include <limits.h>
#include <openssl/pem.h>

using namespace std;

class crypto {
public:
    unsigned char *encrypt_message();//edo

    unsigned char *key_derivation(unsigned char *shared_secret);//edo

    EVP_PKEY *dh_params_gen();//edo

    unsigned char *dh_pubkey(EVP_PKEY *dh_params);//genera public key - edo

    unsigned char *dh_sharedkey(EVP_PKEY *dh_params, EVP_PKEY *public_key, EVP_PKEY *private_key);//edo

    unsigned char* sign(unsigned char *clear_buf, long int clear_size, string prvkey_file_name, char* psw);//lore

    bool verify_sign(unsigned char* sgnt_buf, int *key, long int sgnt_size, unsigned char* clear_buf,long int clear_size,X509_STORE *cert);//lore

    bool verify_cert(X509_STORE *cert);//lore

    //EVP_PKEY *extract_pubkey(X509_STORE *cert);//lore

private:
    void handleError(char* s);//lore
    unsigned char * shared_key; //free it when the session is finished
};


#endif
