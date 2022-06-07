#include "crypto.h"
#include "../Util/util.h"
#include <string.h>
//#include "sodium.h"
#include "sodium/randombytes.h"
#include "sodium/core.h"

using namespace std;

/* Creates a random IV */
void crypto::create_random_iv(unsigned char *iv) {
    int ret;

    ret = RAND_poll();
    if (ret < 0) {
        throw Exception("Error in RAND Poll");
    }

    ret = RAND_bytes(iv, IVSIZE);
    if (ret < 0) {
        throw Exception("Error in RAND bytes");
    }
    /*
    int ret = sodium_init();
    if (ret < 0)
    {
        cerr << "error";
    }
    randombytes_buf(iv, IVSIZE);*/
}

/* Creates a random NONCE */
void crypto::create_nonce(unsigned char *p) {

    int ret;

    ret = RAND_poll();
    if (ret < 0) {
        throw Exception("Error in RAND Poll");
    }

    RAND_bytes(p, NONCESIZE);
    if (ret < 0) {
        throw Exception("Error in RAND bytes");
    }

    /*
    int ret = sodium_init();
    if (ret < 0)
    {
        cerr << "error";
    }
    randombytes_buf(p, NONCESIZE);*/
}

/* Generates ECDH parameters */
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
        throw Exception("Error in params gen");
    }
    if (1 != EVP_PKEY_paramgen_init(pctx)) {
        throw Exception("Error in params gen");
    }
    /* Specific curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) {
        throw Exception("Error in params gen");
    }
    if (1 != EVP_PKEY_paramgen(pctx, &dh_params)) {
        throw Exception("Error in params gen");
    }

    /* Clean up (the params are cleaned after) */
    EVP_PKEY_CTX_free(pctx);
    return dh_params;
}

/* Generates the DH private key */
EVP_PKEY *crypto::dh_keygen() {

    EVP_PKEY *dh_params = this->dh_params_gen();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY *my_prvkey = NULL;
    if (1 != EVP_PKEY_keygen_init(ctx)) {
        throw Exception("Key generation failed");
    }
    if (1 != EVP_PKEY_keygen(ctx, &my_prvkey)) {
        throw Exception("Key generation failed");
    };

    /* Clean up */
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);

    return my_prvkey;
}

/* Generates the DH shared key g^ab */
unsigned char *crypto::dh_sharedkey(EVP_PKEY *my_key, EVP_PKEY *other_pubkey, size_t *size) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);

    if (1 != EVP_PKEY_derive_init(ctx)) {
        throw Exception("Key derivation failed");
    }

    if (1 != EVP_PKEY_derive_set_peer(ctx, other_pubkey)) {
        throw Exception("Key derivation failed");
    }

    unsigned char *secret;
    size_t secretlen;

    if (1 != EVP_PKEY_derive(ctx, NULL, &secretlen)) {
        throw Exception("Error in key derivation");
    }

    secret = (unsigned char *) malloc(secretlen);
    if (secret == NULL) {
        throw Exception("Malloc returned NULL");
    }

    if (1 != EVP_PKEY_derive(ctx, secret, &secretlen)) {
        throw Exception("Error in key derivation");
    }

    /* Clean up */
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(my_key);

    *size = secretlen;

    return secret;
}

/* Derives the session key from the shared key */
unsigned char *crypto::key_derivation(unsigned char *shared_secret, size_t size) {

    const EVP_MD *hash_type = EVP_sha256();
    unsigned char *session_key;
    unsigned char *digest;
    unsigned int digestlen;

    digest = (unsigned char *) malloc(EVP_MD_size(hash_type));
    if (digest == NULL) {
        throw Exception("Malloc returned NULL");;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (1 != EVP_DigestInit(ctx, hash_type)) {
        throw Exception("Key hashing failed");
    };

    if (1 != EVP_DigestUpdate(ctx, (unsigned char *) shared_secret, size)) {
        throw Exception("Key hashing failed");
    };

    if (1 != EVP_DigestFinal(ctx, (unsigned char *) digest, &digestlen)) {
        throw Exception("Key hashing failed");
    };

    EVP_MD_CTX_free(ctx);

    /* Clean up the shared secret */
    unoptimized_memset(shared_secret, 0, size);
    free(shared_secret);

    int session_key_size = 128;

    session_key = (unsigned char *) malloc(session_key_size);
    if (session_key == NULL) {
        throw Exception("Malloc returned NULL");;
    }
    memcpy(session_key, digest, session_key_size);

    /* Clean up digest */
    unoptimized_memset(digest, 0, EVP_MD_size(hash_type));
    free(digest);

    return session_key;
}

/* Encryption of the message */
int crypto::encrypt_packet(unsigned char *plaintext, int plaintext_len,
                           unsigned char *aad, int aad_len,
                           unsigned char *key,
                           unsigned char *iv,
                           unsigned char *ciphertext,
                           unsigned char *tag) {

    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;

    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        throw Exception("Encryption error");
    }

    // Initialise the encryption operation.
    if (1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
        throw Exception("Encryption error");
    }

    // Provide any AAD data. This can be called zero or more times as required
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        throw Exception("Encryption error");
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        throw Exception("Encryption error");
    }
    ciphertext_len = len;

    // Finalize Encryption
    if (1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)) {
        throw Exception("Encryption error");
    }
    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
        throw Exception("Encryption error");
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int crypto::decrypt_message(unsigned char *ciphertext, int ciphertext_len,
                            unsigned char *aad, int aad_len,
                            unsigned char *tag,
                            unsigned char *key,
                            unsigned char *iv,
                            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, current_len;
    int plaintext_len = 0;
    int fragment_size = 1024;
    int decrypted_len = 0;
    int ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        throw Exception("Decryption error");
    }

    if (!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
        throw Exception("Decryption error");
    }

    // Provide any AAD data.
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        throw Exception("Decryption error");
    }

    // Provide the message to be decrypted, and obtain the plaintext output.
    while (decrypted_len < ciphertext_len) {

        current_len = (ciphertext_len - decrypted_len < fragment_size) ? ciphertext_len - decrypted_len : fragment_size;

        if (!EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + decrypted_len, current_len)) {
            throw Exception("Decryption error");
        }
        plaintext_len += len;
        decrypted_len += current_len;
    }

    /* Set expected tag value. */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)) {
        throw Exception("Decryption error");
    }

    /*
     * Finalise the decryption. */
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

/* Verifies the certificate */
bool crypto::verify_cert(X509 *cert) {
    int ret; // used for return values

    // load the CA's certificate:
    char cacert_file_name[] = "./client_file/CA/SecureFileTransfer_cert.pem";

    FILE *cacert_file = fopen(cacert_file_name, "r");
    if (!cacert_file) {

        throw Exception("Cannot open CA cert");
    }

    X509 *cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);

    fclose(cacert_file);
    if (!cacert) {
        throw Exception("Error in PEM_read_X509");
    }

    // load the CRL:
    string crl_file_name = "./client_file/CA/SecureFileTransfer_crl.pem";
    FILE *crl_file = fopen(crl_file_name.c_str(), "r");
    if (!crl_file) {

        throw Exception("Cannot open CRL pem file");
    }

    X509_CRL *crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if (!crl) {
        throw Exception("Error in PEM_read_X509_CRL");
    }

    // build a store with the CA's certificate and the CRL:
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        throw Exception("Error in X509_STORE_new");
    }
    ret = X509_STORE_add_cert(store, cacert);
    if (ret != 1) {
        throw Exception("X509_STORE_add_cert");
    }
    ret = X509_STORE_add_crl(store, crl);
    if (ret != 1) {
        throw Exception("Error in X509_STORE_add_crl");
    }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if (ret != 1) {
        throw Exception("Error in X509_STORE_set_flags");
    }

    // verify the certificate:
    X509_STORE_CTX *certvfy_ctx = X509_STORE_CTX_new();
    if (!certvfy_ctx) {
        throw Exception("Error in X509_STORE_CTX_new");
    }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if (ret != 1) {
        throw Exception("Error in X509_STORE_CTX_init");
    }
    ret = X509_verify_cert(certvfy_ctx);

    /* Clean up */
    X509_STORE_free(store);
    X509_free(cacert);
    X509_CRL_free(crl);
    X509_STORE_CTX_free(certvfy_ctx);

    if (ret != 1) {
        return false;
    } else {
        return true;
    }

}

/* Verifies the signature */
bool crypto::verify_sign(unsigned char *sgnt_buf, long int sgnt_size, unsigned char *clear_buf,
                         long int clear_size, EVP_PKEY *pk) {

    int ret;

    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        throw Exception("Error in EVP_MD_CTX_new");
    }

    ret = EVP_VerifyInit(md_ctx, md);
    if (ret == 0) {
        throw Exception("Error in EVP_VerifyInit");
    }

    ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);
    if (ret == 0) {
        throw Exception("Error in EVP_VerifyUpdate");
    }

    ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, pk);
    if (ret == -1) {
        return false;
    } else if (ret == 0) {
        return false;
    }

    /* Clean up */
    EVP_MD_CTX_free(md_ctx);

    return true;
}

/* Signature generation */
unsigned char *
crypto::signn(unsigned char *clear_buf, long int clear_size, string prvkey_file_name, unsigned int *sgnt_size) {

    int ret; // used for return values

    FILE *prvkey_file = fopen(prvkey_file_name.c_str(), "r");
    if (!prvkey_file) {
        throw Exception("Error in open private key file");
    }

    EVP_PKEY *prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
    fclose(prvkey_file);
    if (!prvkey) {
        throw Exception("Error in fopen");
    }

    // declare some useful variables:
    const EVP_MD *md = EVP_sha256();

    // create the signature context:
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        throw Exception("Error in EVP_MD_CTX_new");
    }

    // allocate buffer for signature:
    unsigned char *sgnt_buf = (unsigned char *) malloc(EVP_PKEY_size(prvkey));
    if (!sgnt_buf) {
        throw Exception("Malloc returned null");
    }

    // sign the plaintext:
    // (perform a single update on the whole plaintext,
    // assuming that the plaintext is not huge)
    ret = EVP_SignInit(md_ctx, md);
    if (ret == 0) {
        throw Exception("Error in EVP_SignInit");
    }
    ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);

    if (ret == 0) {
        throw Exception("Error in EVP_SignUpdate");
    }

    unsigned int prv;
    ret = EVP_SignFinal(md_ctx, sgnt_buf, &prv, prvkey);
    if (ret == 0) {
        throw Exception("EVP_SignFinal");
    }

    *sgnt_size = prv;

    /* Clean up */
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(prvkey);

    return sgnt_buf;

}
