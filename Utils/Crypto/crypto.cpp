#include "crypto.h"

using namespace std;

bool crypto::verify_cert(X509_STORE *cert) {
    int ret; // used for return values

    // load the CA's certificate:
    string cacert_file_name = "SecureFileTransfer_cert.pem";
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

    // load the CRL:
    string crl_file_name = "SecureFileTransfer_crl.pem";
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
        cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        exit(1);
    }
    ret = X509_STORE_add_cert(store, cacert);
    if (ret != 1) {
        cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL)
             << "\n";
        exit(1);
    }
    ret = X509_STORE_add_crl(store, crl);
    if (ret != 1) {
        cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        exit(1);
    }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if (ret != 1) {
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL)
             << "\n";
        exit(1);
    }


    // verify the certificate:
    X509_STORE_CTX *certvfy_ctx = X509_STORE_CTX_new();
    if (!certvfy_ctx) {
        cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        exit(1);
    }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if (ret != 1) {
        cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL)
             << "\n";
        exit(1);
    }
    ret = X509_verify_cert(certvfy_ctx);
    if (ret != 1) {
        cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        return false;
    } else {
        return true;
    }

    //X509_free(cert); da fare comunque dopo
    X509_STORE_free(store);
    X509_free(cacert);
    X509_CRL_free(crl);
    X509_STORE_CTX_free(certvfy_ctx);
}

bool crypto::verify_sign(unsigned char *sgnt_buf, int *key, long int sgnt_size, unsigned char *clear_buf,
                         long int clear_size, X509_STORE *cert) {
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
    ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, X509_get_pubkey(cert));
    if (ret == -1) { // it is 0 if invalid signature, -1 if some other error, 1 if success.
        cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
        return false;
    } else if (ret == 0) {
        cerr << "Error: Invalid signature!\n";
        return false;
    }
    X509_free(cert);
    EVP_MD_CTX_free(md_ctx);
    return true;

}

unsigned char *crypto::sign(unsigned char *clear_buf, long int clear_size, string prvkey_file_name, char *psw) { //remember to free psw
    int ret; // used for return values

    // read my private key file from keyboard:
    FILE *prvkey_file = fopen(prvkey_file_name.c_str(), "r");
    if (!prvkey_file) {
        cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n";
        exit(1);
    }
    EVP_PKEY *prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, psw);
    fclose(prvkey_file);
    if (!prvkey) {
        cerr << "Error: PEM_read_PrivateKey returned NULL\n";
        exit(1);
    }

    // declare some useful variables:
    const EVP_MD *md = EVP_sha256();

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
    ret = EVP_SignInit(md_ctx, md);
    if (ret == 0) {
        cerr << "Error: EVP_SignInit returned " << ret << "\n";
        exit(1);
    }
    ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
    if (ret == 0) {
        cerr << "Error: EVP_SignUpdate returned " << ret << "\n";
        exit(1);
    }
    unsigned int sgnt_size;
    ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
    if (ret == 0) {
        cerr << "Error: EVP_SignFinal returned " << ret << "\n";
        exit(1);
    }

    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(prvkey);

    return sgnt_buf;

    /*deallocate buffers:
    free(clear_buf);
    free(sgnt_buf);
     */
}

