#include "../Crypto/crypto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <regex>

using namespace std;

//--OPCODES
#define CHELLO_OPCODE 0
#define SHELLO_OPCODE 1
#define ACK           10
#define LIST          11
#define DOWNLOAD      12
#define UPLOAD        13
#define RENAME        14
#define DELETE        15
#define LOGOUT        16


using namespace std;

static char* crt_file_pkt(char* filename, int* size, uint8_t opcode, uint16_t counter) {

    int pos1 = 0;
    int ret;
    crypto *c=new crypto();
    FILE *file;
    int aad_size=sizeof(uint8_t)+sizeof(uint16_t)+sizeof(uint32_t);
    unsigned char start_packet[aad_size];
    
    file = fopen(filename, "rb");
    if (file == NULL) {
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
    
    unsigned char* iv = c->create_random_iv();
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    
    unsigned char ciphertext[file_size+16];
    unsigned char tag[16];
    int cipherlen = c->encrypt_message(file,file_size,start_packet,aad_size,c->get_key(), iv, iv_size, ciphertext,tag);
    ret = fclose(file);
    if (ret != 0) {
        printf("Errore\n");
        exit(1);
    }
    char final_packet[aad_size+iv_size+cipherlen+16];
    int pos = 0;
    memcpy(final_packet, start_packet, aad_size);
    pos += aad_size;
    memcpy(final_packet+pos, iv, iv_size);
    pos += iv_size;
    memcpy(final_packet+pos, ciphertext, cipherlen);
    pos += cipherlen;
    memcpy(final_packet+pos, tag, 16);
    pos += 16;

    free(tag);
    free(ciphertext);
    free(start_packet);
    free(iv);

    *size = pos;
    return final_packet;
}

