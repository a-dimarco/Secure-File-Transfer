#include "util.h"
#include "sodium.h"
#include "sodium/randombytes.h"
#include "sodium/core.h"
#include "../Crypto/crypto.h"
using namespace std;
unsigned char *prepare_msg_packet(uint32_t *size, char *msg, int msg_size, uint8_t opcode, int counter2, unsigned char* shared_key)
{
    // PACKET FORMAT: OPCODE - COUNTER - CPSIZE - IV - CIPHERTEXT - TAG)

    int pos = 0;
    uint16_t ct_size=msg_size+16;
    int pkt_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t)+IVSIZE + ct_size + TAGSIZE;
    unsigned char* packet=(unsigned char *)malloc(pkt_len);
    *size = pkt_len;

    memcpy(packet, &opcode, sizeof(opcode)); //OPCode
    pos += sizeof(opcode);

    uint16_t count=htons(counter2);
    memcpy(packet + pos, &count, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    ct_size = htons(ct_size); //CipherText Size
    memcpy(packet + pos, &ct_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    ct_size=ntohs(ct_size);
    int ret;
    crypto *c = new crypto(); //IV
    unsigned char iv[IVSIZE];

    ret=sodium_init();
    if(ret<0){
        cerr << "error";
    }
    randombytes_buf(iv, 12);
    memcpy(packet + pos, iv, 12);
    pos += 12;

    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t); //CipherText & Tag
    unsigned char ct[ct_size];
    unsigned char tag[16];
    c->encrypt_packet((unsigned char *)msg, msg_size, (unsigned char *)packet, aad_size, shared_key, iv, 12, ct, tag);
    memcpy(packet+pos,ct,ct_size);
    pos+=ct_size;
    memcpy(packet+pos,tag,16);
    return packet;
}
unsigned char *crt_file_pkt(char *filename, int *size, uint8_t opcode, uint16_t counter)
{

    int pos1 = 0;
    int ret;
    crypto c = crypto();
    FILE *file;
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    unsigned char start_packet[aad_size];

    file = fopen(filename, "rb");
    if (file == NULL)
    {
        printf("Errore nell'apertura del file\n");
        exit(-1);
    }
    fseek(file, 0L, SEEK_END);
    uint32_t file_size = htonl(ftell(file));
    fseek(file, 0L, SEEK_SET);

    uint16_t n_counter = htons(counter);

    memcpy(start_packet, &opcode, sizeof(uint8_t));
    pos1 += sizeof(uint8_t);
    memcpy(start_packet + pos1, &n_counter, sizeof(uint16_t));
    pos1 += sizeof(uint16_t);
    memcpy(start_packet + pos1, &file_size, sizeof(uint32_t));
    unsigned char iv[EVP_CIPHER_iv_length(EVP_aes_128_gcm())];
    c.create_random_iv(iv);
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());

    unsigned char ciphertext[file_size + 16];
    unsigned char tag[16];
    int cipherlen = c.encrypt_message(file, file_size, start_packet, aad_size, c.get_key(), iv, iv_size, ciphertext, tag);
    ret = fclose(file);
    if (ret != 0)
    {
        printf("Errore\n");
        exit(1);
    }
    unsigned char final_packet[aad_size + iv_size + cipherlen + 16];
    int pos = 0;
    memcpy(final_packet, start_packet, aad_size);
    pos += aad_size;
    memcpy(final_packet + pos, iv, iv_size);
    pos += iv_size;
    memcpy(final_packet + pos, ciphertext, cipherlen);
    pos += cipherlen;
    memcpy(final_packet + pos, tag, 16);
    pos += 16;

    *size = pos;
    return final_packet;
}

bool nameChecker(char *name, int mode)
{ // Checks if file (code = FILENAME) or command (code = COMMAND) is formatted correctly - utility

    bool ret;

    if (mode == FILENAME)
    {
        ret = regex_match(name, regex("^[A-Za-z0-9]*\\.[A-Za-z0-9]+$"));
    }
    else if (mode == COMMAND)
    {
        ret = regex_match(name, regex("^\\![A-Za-z]+$"));
    }
    else
    {
        ret = false;
    }
    return ret;
}

bool file_opener(char *filename, char *username, char* complete_path)
{

    char *path = SERVER_PATH;
    string file_path = path;
    file_path += username;
    path = &file_path[0];
    printf("%s", path);
    FILE *source;

    // Checks if directory exists
    DIR *dir;
    dir = opendir(path);
    if (dir)
    {
        printf("Directory - OK\n");
    }
    else
    {
        printf("Directory NOT found\n");
        exit(-1);
    }

    closedir(dir);
    // printf("Selected Directory : %s \n" , path);
    file_path += "/file/";
    //printf("Filepath %s\n", file_path);
    // Add Filename to path
    //strcpy(path + strlen(path), "/");
    //strcpy(path + strlen(path), filename);
    file_path += filename;
    //printf("Filepath %s\n", file_path);
    printf("fileopener1\n");
    size_t len = file_path.length()+1;//strlen(path) - 1;
    printf("%d\n", len);
    printf("fileopener2\n");
    char *filePath = &file_path[0];
    //memcpy(filePath, path, len);
    printf("fileopener3\n");
    printf("filepath %s\n", filePath);
    // Open the file
    source = fopen(filePath, "rb");
    printf("fileopener4\n");
    if (source == NULL)
    {
    	printf("boh\n");
        //fclose(source);
        //free(filePath);
        printf("File not found\n");
        return true;
    }
    else
    {
    	char* pth = (char*)malloc(len);
    	strcpy(pth, file_path.c_str());
    	complete_path = pth;
    	//printf("%s\n", complete_path);
    	//complete_path[len-1] = '\0';
        printf("File found\n");
        fclose(source);
        //free(filePath);
        return false;
    }
}

unsigned char* crt_request_pkt(char* filename, int* size, uint8_t opcode, uint16_t counter, unsigned char* shared_key) {

	crypto c = crypto();
	
	int aad_size = sizeof(uint8_t)+sizeof(uint16_t)*2;
	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
	uint16_t ptext_size = htons(strlen(filename) + 1);
	int pos = 0;
	int cipherlen;
	uint16_t n_counter = htons(counter);
	*size = aad_size+iv_size+ptext_size+2*16;
	
	unsigned char* pkt = (unsigned char*)malloc(*size);
    unsigned char iv[EVP_CIPHER_iv_length(EVP_aes_128_gcm())];
	c.create_random_iv(iv);
	unsigned char tag[TAGSIZE];
	//unsigned char* ciphertext = (unsigned char*)malloc(ptext_size+16);
	
	memcpy(pkt, &opcode, sizeof(uint8_t));
	pos += sizeof(uint8_t);
	memcpy(pkt+pos, &n_counter, sizeof(uint16_t));
	pos += sizeof(uint16_t);
	memcpy(pkt+pos, &ptext_size, sizeof(uint16_t));
	pos += sizeof(uint16_t);
	memcpy(pkt+pos, iv, iv_size);
	pos += iv_size;
	 
	
	cipherlen = c.encrypt_packet((unsigned char*)filename, strlen(filename)+1,
                           (unsigned char*)pkt, aad_size, shared_key, iv, iv_size,
                           (unsigned char*)pkt+pos, tag);
        
        pos += cipherlen;
        memcpy(pkt+pos, tag, 16);
        return pkt;  
}


