#include "crypto.h"
#include <string.h>
#include "sodium.h"
#include "sodium/randombytes.h"
#include "sodium/core.h"

using namespace std;

unsigned char *crypto::get_key() {
    return this->shared_key;
}

void crypto::create_random_iv(unsigned char * iv) {
    /*RAND_poll();
    RAND_bytes(iv, EVP_CIPHER_iv_length(EVP_aes_128_gcm()));*/
    int ret=sodium_init();
    if(ret<0){
        cerr << "error";
    }
    randombytes_buf(iv, IVSIZE);

}

/*unsigned char *crypto::create_nonce() {
    RAND_poll();
    unsigned char nonce[8];
    RAND_bytes(nonce, 8);
    return nonce;
}*/

void crypto::create_nonce(unsigned char* p) {
    //RAND_poll();
    //unsigned char nonce[8];
    //RAND_bytes(p, 8);
    //return nonce;
    int ret=sodium_init();
    if(ret<0){
        cerr << "error";
    }
    randombytes_buf(p, NONCESIZE);
}

EVP_PKEY *crypto::dh_params_gen() {

    /*
    EVP_PKEY* dh_params;
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());
    */

    EVP_PKEY *dh_params = NULL;
    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        printf("Errore nella dh_params_gen");
        exit(-1);
    }
    if (1 != EVP_PKEY_paramgen_init(pctx)) {
        printf("Errore nella dh_params_gen");
        exit(-1);
    }
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) {
        printf("Errore nella dh_params_gen");
        exit(-1);
    }
    if (1 != EVP_PKEY_paramgen(pctx, &dh_params)) {
        printf("Errore nella dh_params_gen");
        exit(-1);
    }
    EVP_PKEY_CTX_free(pctx);
    return dh_params;


}

EVP_PKEY *crypto::dh_keygen() {
    EVP_PKEY * dh_params=this->dh_params_gen();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY *my_prvkey = NULL;
    if (1 != EVP_PKEY_keygen_init(ctx)) {
        printf("Key generation failed\n");
        exit(-1);
    }
    if (1 != EVP_PKEY_keygen(ctx, &my_prvkey)) {
        printf("Key generation failed\n");
        exit(-1);
    };
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);
    return my_prvkey;
}


unsigned char *crypto::dh_sharedkey(EVP_PKEY *my_key, EVP_PKEY *other_pubkey, size_t *size) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);

    if (1 != EVP_PKEY_derive_init(ctx)) {
        printf("Error in key derivation\n");
        exit(-1);
    }

    if (1 != EVP_PKEY_derive_set_peer(ctx, other_pubkey)) {
        printf("Error in key derivation\n");
        exit(-1);
    }

    unsigned char *secret;
    size_t secretlen;

    if (1 != EVP_PKEY_derive(ctx, NULL, &secretlen)) {
        printf("Error in key derivation\n");
        exit(-1);
    }


    secret = (unsigned char *) malloc(secretlen);
    if (secret == NULL) {
        printf("Error in key derivation\n");
        exit(-1);
    }

    if (1 != EVP_PKEY_derive(ctx, secret, &secretlen)) {
        printf("Error in key derivation\n");
        exit(-1);
    }

    EVP_PKEY_CTX_free(ctx);

    EVP_PKEY_free(my_key);
    *size = secretlen;

    return secret;
}

unsigned char *crypto::key_derivation(unsigned char *shared_secret, size_t size) {

    const EVP_MD *hash_type = EVP_sha256();

    unsigned char *session_key;
    unsigned char *digest;

    unsigned int digestlen;

    digest = (unsigned char *) malloc(EVP_MD_size(hash_type));
    if (digest == NULL) {
        printf("Error in key derivation\n");
        exit(-1);
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (1 != EVP_DigestInit(ctx, hash_type)) {
        printf("Key hashing failed\n");
        exit(-1);
    };

    if (1 != EVP_DigestUpdate(ctx, (unsigned char *) shared_secret, size)) {
        printf("Key hashing failed\n");
        exit(-1);
    };

    if (1 != EVP_DigestFinal(ctx, (unsigned char *) digest, &digestlen)) {
        printf("Key hashing failed\n");
        exit(-1);
    };

    EVP_MD_CTX_free(ctx);

#pragma optimize("", off);
    memset(shared_secret, 0, size);
    free(shared_secret);
#pragma optimize("", on);

    int session_key_size = 128;
    session_key = (unsigned char *) malloc(session_key_size);
    memcpy(session_key, digest, session_key_size);

#pragma optimize("", off);
    memset(digest, 0, EVP_MD_size(hash_type));
#pragma optimize("", on);


    return session_key;
}

int crypto::encrypt_message(FILE *file, int plaintext_len,
                            unsigned char *aad, int aad_len,
                            unsigned char *key,
                            unsigned char *iv, int iv_len,
                            unsigned char *ciphertext,
                            unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;
    int encrypted_len = 0;
    int fragment_size = 1024;
    int current_len, ret;
    unsigned char *fragment;

    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Errore nella encrypt_msg\n");
        exit(-1);
    }
    // Initialise the encryption operation.
    if (1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
        printf("Errore nella encrypt_msg\n");
        exit(-1);
    }

    // Provide any AAD data. This can be called zero or more times as required
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        printf("Errore nella encrypt_msg\n");
        exit(-1);
    }

    while (encrypted_len < plaintext_len) {

        current_len = (plaintext_len - encrypted_len < fragment_size) ? plaintext_len - encrypted_len : fragment_size;

        fragment = (unsigned char *) malloc(current_len);

        ret = fread(fragment, sizeof(unsigned char), current_len, file);
        if (ret < current_len) {
            printf("Error fread\n");
            exit(1);
        }

        if (1 != EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, fragment, current_len)) {
            printf("Errore nella encrypt_msg\n");
            exit(-1);
        }
        ciphertext_len += len;

        free(fragment);
        encrypted_len += current_len;
    };

    // Finalize Encryption
    if (1 != EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &len)) {
        printf("Errore nella encrypt_msg\n");
        exit(-1);
    }
    ciphertext_len += len;
    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
        printf("Errore nella encrypt_msg\n");
        exit(-1);
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int crypto::encrypt_packet(unsigned char *plaintext, int plaintext_len,
                           unsigned char *aad, int aad_len,
                           unsigned char *key,
                           unsigned char *iv, int iv_len,
                           unsigned char *ciphertext,
                           unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;
    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Errore nella encrypt_packet\n");
        exit(-1);
    }
    // Initialise the encryption operation.
    if (1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
        printf("Errore nella encrypt_packet\n");
        exit(-1);
    }

    // Provide any AAD data. This can be called zero or more times as required
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        printf("Errore nella encrypt_packet\n");
        exit(-1);
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        printf("Errore nella encrypt_packet\n");
        exit(-1);
    }
    ciphertext_len = len;
    // Finalize Encryption
    if (1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)) {
        printf("Errore nella encrypt_packet\n");
        exit(-1);
    }
    ciphertext_len += len;
    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
        printf("Errore nella encrypt_packet\n");
        exit(-1);
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int crypto::decrypt_message(unsigned char *ciphertext, int ciphertext_len,
                            unsigned char *aad, int aad_len,
                            unsigned char *tag,
                            unsigned char *key,
                            unsigned char *iv, int iv_len,
                            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, current_len;
    int plaintext_len = 0;
    int fragment_size = 1024;
    int decrypted_len = 0;
    int ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Errore nella decrypt_message\n");
        exit(-1);
    }
    if (!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
        printf("Errore nella decrypt_message\n");
        exit(-1);
    }
    // Provide any AAD data.
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        printf("Errore nella decrypt_message\n");
        exit(-1);
    }
    // Provide the message to be decrypted, and obtain the plaintext output.

    while (decrypted_len < ciphertext_len) {

        current_len = (ciphertext_len - decrypted_len < fragment_size) ? ciphertext_len - decrypted_len : fragment_size;

        if (!EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + decrypted_len, current_len)) {
            printf("Errore nel while della decrypt\n");
            exit(-1);
        }
        plaintext_len += len;
        decrypted_len += current_len;
    }
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)) {
        printf("Errore nella decrypt_message\n");
        exit(-1);
    }
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + plaintext_len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);

    if (ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

bool crypto::verify_cert(X509 *cert) {
    int ret; // used for return values

    // load the CA's certificate:
    //string cacert_file_name = "/home/studenti/Documents/GitHub/Secure-File-Transfer/server_file/server/SecureFileTransfer_cert.pem";
    char cacert_file_name[] = "./server_file/server/SecureFileTransfer_cert.pem";

    FILE *cacert_file = fopen(cacert_file_name, "r");
    if (!cacert_file) {

        cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n";
        exit(1);
    }
    X509 *cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if (!cacert) {
        cerr << "Error: PEM_read_X509 returned NULL\n";
        exit(1);
    }

    // load the CRL:
    string crl_file_name = "./server_file/server/SecureFileTransfer_crl.pem";
    FILE *crl_file = fopen(crl_file_name.c_str(), "r");
    if (!crl_file) {

        cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n";
        exit(1);
    }
    X509_CRL *crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if (!crl) {
        cerr << "Error: PEM_read_X509_CRL returned NULL\n";
        exit(1);
    }

    // build a store with the CA's certificate and the CRL:
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        cerr << "Error: X509_STORE_new returned NULL\n"
             << ERR_error_string(ERR_get_error(), NULL) << "\n";
        exit(1);
    }
    ret = X509_STORE_add_cert(store, cacert);
    if (ret != 1) {
        cerr << "Error: X509_STORE_add_cert returned " << ret << "\n"
             << ERR_error_string(ERR_get_error(), NULL)
             << "\n";
        exit(1);
    }
    ret = X509_STORE_add_crl(store, crl);
    if (ret != 1) {
        cerr << "Error: X509_STORE_add_crl returned " << ret << "\n"
             << ERR_error_string(ERR_get_error(), NULL) << "\n";
        exit(1);
    }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if (ret != 1) {
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n"
             << ERR_error_string(ERR_get_error(), NULL)
             << "\n";
        exit(1);
    }

    // verify the certificate:
    X509_STORE_CTX *certvfy_ctx = X509_STORE_CTX_new();
    if (!certvfy_ctx) {
        cerr << "Error: X509_STORE_CTX_new returned NULL\n"
             << ERR_error_string(ERR_get_error(), NULL) << "\n";
        exit(1);
    }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if (ret != 1) {
        cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n"
             << ERR_error_string(ERR_get_error(), NULL)
             << "\n";
        exit(1);
    }
    ret = X509_verify_cert(certvfy_ctx);
    X509_STORE_free(store);
    X509_free(cacert);
    X509_CRL_free(crl);
    X509_STORE_CTX_free(certvfy_ctx);
    if (ret != 1) {
        cerr << "Error: X509_verify_cert returned " << ret << "\n"
             << ERR_error_string(ERR_get_error(), NULL) << "\n";
        return false;
    } else {
        return true;
    }

    // X509_free(cert); da fare comunque dopo

}

bool crypto::verify_sign(unsigned char *sgnt_buf, long int sgnt_size, unsigned char *clear_buf,
                         long int clear_size, EVP_PKEY* pk) {
    int ret;
    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        cerr << "Error: EVP_MD_CTX_new returned NULL\n";
        exit(1);
    }
    ret = EVP_VerifyInit(md_ctx, md);
    if (ret == 0) {
        cerr << "Error: EVP_VerifyInit returned " << ret << "\n";
        exit(1);
    }
    ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);
    if (ret == 0) {
        cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n";
        exit(1);
    }
    ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, pk);

    if (ret == -1) { // it is 0 if invalid signature, -1 if some other error, 1 if success.
        cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
        return false;
    } else if (ret == 0) {
        //cerr << "Error: Invalid signature!\n";
        return false;
    }
    EVP_MD_CTX_free(md_ctx);
    return true;
}
unsigned char *crypto::signn(unsigned char *clear_buf, long int clear_size, string prvkey_file_name, unsigned int* sgnt_size) {
    int ret; // used for return values

    FILE* prvkey_file = fopen(prvkey_file_name.c_str(), "r");
    if(!prvkey_file){ cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n"; exit(1); }
    EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
    fclose(prvkey_file);
    if(!prvkey){ cerr << "Error: PEM_read_PrivateKey returned NULL\n"; exit(1); }

    // declare some useful variables:
    const EVP_MD* md = EVP_sha256();

    // create the signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

    // allocate buffer for signature:
    //unsigned char* sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(prvkey));
    unsigned char* sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(prvkey));

    if(!sgnt_buf) { cerr << "Error: malloc returned NULL (signature too big?)\n"; exit(1); }

    // sign the plaintext:
    // (perform a single update on the whole plaintext,
    // assuming that the plaintext is not huge)
    ret = EVP_SignInit(md_ctx, md);
    if(ret == 0){ cerr << "Error: EVP_SignInit returned " << ret << "\n"; exit(1); }
    ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);

    if(ret == 0){ cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; exit(1); }
    unsigned int prv;
    ret = EVP_SignFinal(md_ctx, sgnt_buf, &prv, prvkey);
    if(ret == 0){ cerr << "Error: EVP_SignFinal returned " << ret << "\n"; exit(1); }

    *sgnt_size=prv;
    //printf("signature size: %d",prv);
    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(prvkey);


    return sgnt_buf;

    // deallocate buffers:
    free(clear_buf);
    free(sgnt_buf);

}
