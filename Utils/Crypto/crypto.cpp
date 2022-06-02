#include "crypto.h"
#include <string.h>
#pragma once
using namespace std;

unsigned char *crypto::get_key() {
    return this->shared_key;
}

void crypto::create_random_iv(unsigned char * iv) {
    RAND_poll();
    RAND_bytes(iv, EVP_CIPHER_iv_length(EVP_aes_128_gcm()));

}

/*unsigned char *crypto::create_nonce() {
    RAND_poll();
    unsigned char nonce[8];
    RAND_bytes(nonce, 8);
    return nonce;
}*/

void crypto::create_nonce(unsigned char* p) {
    RAND_poll();
    //unsigned char nonce[8];
    RAND_bytes(p, 8);
    //return nonce;
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

void crypto::serialize_dh_pubkey(EVP_PKEY *dh_key, char* pubkey) {
    BIO* bio=BIO_new(BIO_s_mem());
    int ret= PEM_write_bio_PUBKEY(bio, dh_key);
    if (ret == 0) {
        cerr << "Error: PEM_write_bio_PUBKEY returned " << ret << "\n";
        exit(1);
    }
    
    char ** key;
    long s=BIO_get_mem_data(bio,key);
    
    pubkey=(char *)malloc(s);
    memcpy(pubkey,*key,s);
    //pubkey=*key;
    

}
/*
EVP_PKEY *crypto::deserialize_dh_pubkey(unsigned char *dh_key) {

    int ret;
    FILE *file = fopen("other_pubkey", "wb");
    if (file == NULL) {
        printf("fopen non riuscita - deser_dh_pubkey\n");
        exit(-1);
    }
    ret = fwrite(dh_key, sizeof(unsigned char), size, file);
    if (ret < size) {
        printf("Error fwrite - deser_dh_pubkey\n");
        exit(-1);
    }
    if (0 != fclose(file)) {
        printf("errore - deser_dh_pubkey\n");
        exit(-1);
    }

    file = fopen("dh_pubkey", "r");
    if (file == NULL) {
        printf("fopen non riuscita - deser_dh_pubkey\n");
        exit(-1);
    }

    EVP_PKEY *pub_key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if (pub_key == NULL) {
        printf("errore readpubkey - deser_dh_pubkey\n");
        exit(-1);
    }
    ret = fclose(file);
    if (ret != 0) {
        printf("Error fclose - deser_dh_pubkey\n");
        exit(-1);
    }

    return pub_key;
}
 */

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
    printf("key derivation ok\n");
    EVP_PKEY_CTX_free(ctx);

    EVP_PKEY_free(my_key);
    *size = secretlen;
    
    return secret;
}

unsigned char *crypto::key_derivation(unsigned char *shared_secret, size_t size) {

    const EVP_MD *hash_type = EVP_sha256();

    unsigned char *session_key;
    unsigned char *digest;

    int keylen;
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
#pragma optimize("", on);

    int session_key_size = 128;
    session_key = (unsigned char *) malloc(session_key_size);
    memcpy(session_key, digest, session_key_size);

#pragma optimize("", off);
    memset(digest, 0, EVP_MD_size(hash_type));
#pragma optimize("", on);
    printf("session key generated\n");
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
    printf("msg len %d\n", plaintext_len);
    printf("ciph_len %d\n",ciphertext_len);
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

/*

int main() {
    crypto c = crypto();
    EVP_PKEY *dh_params = c.dh_params_gen();
    EVP_PKEY *my_key = c.dh_keygen(dh_params);
    long size;
    unsigned char *pubkey = c.serialize_dh_pubkey(my_key, &size);
    printf("%d\n", size);
    EVP_PKEY *my_pubkey = c.deserialize_dh_pubkey(pubkey, size);

    EVP_PKEY *other_key = c.dh_keygen(dh_params);
    pubkey = c.serialize_dh_pubkey(other_key, &size);
    EVP_PKEY *other_pubkey = c.deserialize_dh_pubkey(pubkey, size);

    size_t s;
    unsigned char *secret = c.dh_sharedkey(my_key, other_pubkey, &s);

    unsigned char *session_key = c.key_derivation(secret, s);

    return 0;
}

 */

bool crypto::verify_cert(X509 *cert) {
    int ret; // used for return values

    // load the CA's certificate:
    //string cacert_file_name = "/home/studenti/Documents/GitHub/Secure-File-Transfer/server_file/server/SecureFileTransfer_cert.pem";
    char cacert_file_name[] = "./server_file/server/SecureFileTransfer_cert.pem";
    printf("Paolo\n");
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
        cerr << "Error: Invalid signature!\n";
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

    printf("signature created\n");
    return sgnt_buf;

    // deallocate buffers:
    free(clear_buf);
    free(sgnt_buf);

}

int crypto::testverify(){
    int ret; // used for return values


    // load the CA's certificate:
    string cacert_file_name="./server_file/server/SecureFileTransfer_cert.pem";
    FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
    if(!cacert_file){ cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; exit(1); }
    X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

    // load the CRL:
    string crl_file_name="./server_file/server/SecureFileTransfer_crl.pem";
    FILE* crl_file = fopen(crl_file_name.c_str(), "r");
    if(!crl_file){ cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n"; exit(1); }
    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl){ cerr << "Error: PEM_read_X509_CRL returned NULL\n"; exit(1); }

    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();
    if(!store) { cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_STORE_add_cert(store, cacert);
    if(ret != 1) { cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) { cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

    // load the peer's certificate:
    string cert_file_name;
    cout << "Please, type the PEM file containing peer's certificate: ";
    getline(cin, cert_file_name);
    if(!cin) { cerr << "Error during input\n"; exit(1); }
    FILE* cert_file = fopen(cert_file_name.c_str(), "r");
    if(!cert_file){ cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; exit(1); }
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!cert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

    // verify the certificate:
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if(ret != 1) { cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_verify_cert(certvfy_ctx);
    if(ret != 1) { cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

    // print the successful verification to screen:
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
    free(tmp);
    free(tmp2);

    // load the signature file:
    string sgnt_file_name;
    cout << "Please, type the signature file: ";
    getline(cin, sgnt_file_name);
    if(!cin) { cerr << "Error during input\n"; exit(1); }
    FILE* sgnt_file = fopen(sgnt_file_name.c_str(), "rb");
    if(!sgnt_file) { cerr << "Error: cannot open file '" << sgnt_file_name << "' (file does not exist?)\n"; exit(1); }

    // get the file size:
    // (assuming no failures in fseek() and ftell())
    fseek(sgnt_file, 0, SEEK_END);
    long int sgnt_size = ftell(sgnt_file);
    fseek(sgnt_file, 0, SEEK_SET);

    // read the signature from file:
    unsigned char* sgnt_buf = (unsigned char*)malloc(sgnt_size);
    if(!sgnt_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
    ret = fread(sgnt_buf, 1, sgnt_size, sgnt_file);
    if(ret < sgnt_size) { cerr << "Error while reading file '" << sgnt_file_name << "'\n"; exit(1); }
    fclose(sgnt_file);

    // declare some useful variables:
    const EVP_MD* md = EVP_sha256();
    // read the file to verify from keyboard:
    string clear_file_name;
    cout << "Please, type the file to verify: ";
    getline(cin, clear_file_name);
    if(!cin) { cerr << "Error during input\n"; exit(1); }

    // open the file to verify:
    FILE* clear_file = fopen(clear_file_name.c_str(), "rb");
    if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n"; exit(1); }

    // get the file size:
    // (assuming no failures in fseek() and ftell())
    fseek(clear_file, 0, SEEK_END);
    long int clear_size = ftell(clear_file);
    fseek(clear_file, 0, SEEK_SET);

    // read the plaintext from file:
    unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
    if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
    ret = fread(clear_buf, 1, clear_size, clear_file);
    if(ret < clear_size) { cerr << "Error while reading file '" << clear_file_name << "'\n"; exit(1); }
    fclose(clear_file);

    // create the signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

    // verify the plaintext:
    // (perform a single update on the whole plaintext,
    // assuming that the plaintext is not huge)
    ret = EVP_VerifyInit(md_ctx, md);
    if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }
    ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);
    if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
    ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, X509_get_pubkey(cert));
    if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
        cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
        exit(1);
    }else if(ret == 0){
        cerr << "Error: Invalid signature!\n";
        exit(1);
    }

    // print the successful signature verification to screen:
    cout << "The Signature has been correctly verified! The message is authentic!\n";

    // deallocate data:
    EVP_MD_CTX_free(md_ctx);
    X509_free(cert);
    X509_STORE_free(store);
    //X509_free(cacert); // already deallocated by X509_STORE_free()
    //X509_CRL_free(crl); // already deallocated by X509_STORE_free()
    X509_STORE_CTX_free(certvfy_ctx);

    return 0;
}

unsigned char *crypto::sign(unsigned char *clear_buf, long int clear_size, string prvkey_file_name, char* psw, unsigned int* sgnt_size) {            // remember to free psw
    int ret; // used for return values

    // read my private key file from keyboard:
    FILE *prvkey_file = fopen(prvkey_file_name.c_str(), "r");
    if (!prvkey_file) {
        cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n";
        exit(1);
    }
    
    EVP_PKEY *prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, (void *) "pippo");
    if(prvkey == NULL){
        printf("Error reading prvt_key\n");
        exit(1);
    }

    fclose(prvkey_file);
    if (!prvkey) {
        cerr << "Error: PEM_read_PrivateKey returned NULL\n";
        exit(1);
    }

    // declare some useful variables:
    //const EVP_MD *md = EVP_sha256();
    // create the signature context:
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        cerr << "Error: EVP_MD_CTX_new returned NULL\n";
        exit(1);
    }


    
    // allocate buffer for signature:
    unsigned char *sgnt_buf = (unsigned char *) malloc(EVP_PKEY_size(prvkey));
    if (!sgnt_buf) {
        cerr << "Error: malloc returned NULL (signature too big?)\n";
        exit(1);
    }
    
    // sign the plaintext:
    // (perform a single update on the whole plaintext,
    // assuming that the plaintext is not huge)
    //ret = EVP_SignInit(md_ctx, md);
    ret = EVP_SignInit(md_ctx, EVP_sha256());
    if (ret ==0) {
        cerr << "Error: EVP_SignInit returned " << ret << "\n";
        exit(1);
    }
    
    int current_size;
    int signed_size=0;
    
    while(signed_size<clear_size) {
        current_size=(clear_size-signed_size<10) ? clear_size-signed_size : 10;
        ret = EVP_SignUpdate(md_ctx, clear_buf+signed_size, current_size);
        if (ret ==0) {
            cerr << "Error: EVP_SignUpdate returned " << ret << "\n";
            exit(1);
        }
        signed_size+=current_size;
        
    }
    
    ret = EVP_SignFinal(md_ctx, sgnt_buf, sgnt_size, prvkey);
    
    if (ret ==0) {
        cerr << "Error: EVP_SignFinal returned " << ret << "\n";
        exit(1);
    }
    printf("sign ok\n");

    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(prvkey);

    return sgnt_buf;

    /*deallocate buffers:
    free(clear_buf);
    free(sgnt_buf);
     */
}

unsigned char *crypto::getServerCert(uint32_t *size) {
    string cacert_file_name = "./server_file/server/SecureFileTransfer_cert.pem";
    FILE *cacert_file = fopen(cacert_file_name.c_str(), "r");
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
    BIO* bio=BIO_new(BIO_s_mem());
    int ret= PEM_write_bio_X509(bio, cacert);
    if (ret == 0) {
        cerr << "Error: PEM_write_bio_X509 returned " << ret << "\n";
        exit(1);
    }
    unsigned char * cert;
    long s=BIO_get_mem_data(bio, &cert);;
    ret= BIO_read(bio, cert, s);
    if(ret<1){
        cerr<<"Bio blu";
    }
    BIO_free(bio);
    return cert;
}
