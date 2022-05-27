#include "crypto.h"

EVP_PKEY* crypto::dh_params_gen() {
	/*
	EVP_PKEY* dh_params;
	dh_params = EVP_PKEY_new();
	EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());
	*/
	
	EVP_PKEY* dh_params = NULL;
	EVP_PKEY_CTX* pctx;
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

EVP_PKEY* crypto::dh_keygen(EVP_PKEY *dh_params) {

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, NULL);
	EVP_PKEY* my_prvkey = NULL;
	if (1 != EVP_PKEY_keygen_init(ctx)) {
		printf("Key generation failed\n");
		exit(-1);
	}
	if (1 != EVP_PKEY_keygen(ctx, &my_prvkey)) {
		printf("Key generation failed\n");
		exit(-1);
	};
	EVP_PKEY_CTX_free(ctx);
	return my_prvkey;
}

unsigned char* crypto::serialize_dh_pubkey(EVP_PKEY *dh_key, long* size) {
	
	FILE* file = fopen("dh_pubkey", "w");
	if (file == NULL) {
		printf("fopen non riuscita - dh_pubkey\n");
		exit(-1);
	}	
	if (1 != PEM_write_PUBKEY(file, dh_key)) {
		printf("errore - dh_pubkey\n");
		exit(-1);
	}
	if (0 != fclose(file)) {
		printf("errore - dh_pubkey\n");
		exit(-1);
	}
	
	file = fopen("dh_pubkey", "rb");
	if (file == NULL) {
		printf("fopen non riuscita - dh_pubkey\n");
		exit(-1);
	}	
	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	printf("File size: %ld\n", file_size);
	fseek(file, 0, SEEK_SET);
	
	unsigned char* pem_pubkey = (unsigned char*)malloc(file_size);
	if (pem_pubkey == NULL) {
		printf("malloc non riuscita - dh_pubkey\n");
		exit(-1);
	}
	
	int ret = fread(pem_pubkey, sizeof(unsigned char), file_size, file);
	if (ret < file_size) {
		printf("Error fread - dh_pubkey\n");
		exit(1);
	}
	ret = fclose(file);
	if (ret != 0) {
		printf("Error fclose - dh_pubkey\n");
		exit(1);
	}
	
	*size = file_size;
	printf("%s", pem_pubkey);
	return pem_pubkey;
	/*
	int pkeyLen;
	unsigned char* ucBuf, *ucTempBuf;
	pkeyLen = i2d_PublicKey(dh_key, NULL);
	printf("%d\n", pkeyLen);
	ucBuf = (unsigned char*)malloc(pkeyLen+1);
	
	i2d_PublicKey(dh_key, &ucBuf);
	
	int ii;
	for (ii = 0; ii < pkeyLen; ii++)
		printf("%c\n", (unsigned char)ucBuf[ii]);
	return ucBuf;	*/
}

EVP_PKEY* crypto::deserialize_dh_pubkey(unsigned char *dh_key, long size) {
	
	int ret;
	FILE* file = fopen("other_pubkey", "wb");
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
	
	EVP_PKEY* pub_key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
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

unsigned char* crypto::dh_sharedkey(EVP_PKEY *my_key, EVP_PKEY *other_pubkey, size_t* size) {

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_key, NULL);
	
	if (1 != EVP_PKEY_derive_init(ctx)) {
		printf("Error in key derivation\n");
		exit(-1);
	}
	if (1 != EVP_PKEY_derive_set_peer(ctx, other_pubkey)) {
		printf("Error in key derivation\n");
		exit(-1);
	}
	unsigned char* secret;
	size_t secretlen;
	
	if (1 != EVP_PKEY_derive(ctx, NULL, &secretlen)) {
		printf("Error in key derivation\n");
		exit(-1);
	}	
	
	secret = (unsigned char*)malloc(secretlen);
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

unsigned char* crypto::key_derivation(unsigned char *shared_secret, size_t size) {
	
	const EVP_MD* hash_type = EVP_sha256();
	
	unsigned char* session_key;
	unsigned char* digest;
	
	int keylen;
	unsigned int digestlen;
	
	digest = (unsigned char*)malloc(EVP_MD_size(hash_type));
	if (digest == NULL) {
		printf("Error in key derivation\n");
		exit(-1);
	}
	
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (1 != EVP_DigestInit(ctx, hash_type)) {
		printf("Key hashing failed\n");
		exit(-1);
	};	
	if (1 != EVP_DigestUpdate(ctx, (unsigned char*)shared_secret, size)) {
		printf("Key hashing failed\n");
		exit(-1);
	};
	if (1 != EVP_DigestFinal(ctx, (unsigned char*)digest, &digestlen)) {
		printf("Key hashing failed\n");
		exit(-1);
	};
	
	EVP_MD_CTX_free(ctx);
	
	#pragma optimize("", off);
	memset(shared_secret, 0, size);
	#pragma optimize("", on);
	
	int session_key_size = 128;
	session_key = (unsigned char*)malloc(session_key_size);
	memcpy(session_key, digest, session_key_size);
	
	#pragma optimize("", off);
	memset(digest, 0, EVP_MD_size(hash_type));
	#pragma optimize("", on);
	
	return session_key;		
}

int crypto::encrypt_message(const char* filename, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    FILE* file;
    int len=0;
    int ciphertext_len=0;
    int encrypted_len=0;
    int fragment_size=1024;
    int current_len, ret;
    unsigned char* fragment;
    
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
    	printf("Errore nella encrypt_msg\n");
    	exit(-1);
    }
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
    	printf("Errore nella encrypt_msg\n");
    	exit(-1);
    }

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
    	printf("Errore nella encrypt_msg\n");
    	exit(-1);
    }

    while (encrypted_len < plaintext_len) {
    
    	file = fopen(filename, "rb");
    	if (file == NULL) {
    		printf("Errore nella encrypt_msg\n");
    		exit(-1);
    	}
    	current_len = (plaintext_len-encrypted_len < fragment_size) ? plaintext_len-encrypted_len : fragment_size;
    
    	fragment = (unsigned char*)malloc(current_len);
    
    	ret = fread(fragment, sizeof(unsigned char), current_len, file);
	if (ret < current_len) {
		printf("Error fread\n");
		exit(1);
	}
    	
    	ret = fclose(file);
	if (ret != 0) {
		printf("Errore nella encrypt_msg\n");
		exit(1);
	}
    	
    	if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, fragment, current_len))  {
    		printf("Errore nella encrypt_msg\n");
    		exit(-1);
    	}	
    	ciphertext_len += len;
    	
    	free(fragment);
    	encrypted_len += current_len;
    };
	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &len)) {
    		printf("Errore nella encrypt_msg\n");
    		exit(-1);
    	}	
    ciphertext_len += len;
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
    		printf("Errore nella encrypt_msg\n");
    		exit(-1);
    	}	
        
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int main(){
	crypto c = crypto();	
	EVP_PKEY* dh_params = c.dh_params_gen();
	EVP_PKEY* my_key = c.dh_keygen(dh_params);
	long size;
	unsigned char* pubkey = c.serialize_dh_pubkey(my_key, &size);
	printf("%d\n", size);
	EVP_PKEY* my_pubkey = c.deserialize_dh_pubkey(pubkey, size);
	
	EVP_PKEY* other_key = c.dh_keygen(dh_params);
	pubkey = c.serialize_dh_pubkey(other_key, &size);
	EVP_PKEY* other_pubkey = c.deserialize_dh_pubkey(pubkey, size);
	
	size_t s;
	unsigned char* secret = c.dh_sharedkey(my_key, other_pubkey, &s);
	
	unsigned char* session_key = c.key_derivation(secret, s);
	
	return 0;
}



