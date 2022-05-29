#include "util.h"
using namespace std;

char* crt_file_pkt(char* filename, int* size, uint8_t opcode, uint16_t counter) {

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

bool nameChecker(char *name, int mode) {//Checks if file (code = FILENAME) or command (code = COMMAND) is formatted correctly - utility

    bool ret;
    size_t len = strlen(name) - 1;
    char *filename = (char *) malloc(len);
    memcpy(filename, name, len);
    //printf("Test: %s\n", test);
    if (mode == FILENAME) {
        ret = regex_match(filename, regex("^[A-Za-z0-9]*\\.[A-Za-z0-9]+$"));
    } else if (mode == COMMAND) {
        ret = regex_match(filename, regex("^\\![A-Za-z]+$"));
    } else {
        ret = false;
    }
    free(filename);
    return ret;

}

bool file_opener(char* filename, char* username){

    char *path=CLIENT_PATH;
    string file_path = path;
    file_path += username;
    path = &file_path[0];
    printf("%s",path);
    FILE *source;

    //Checks if directory exists
    DIR *dir;
    dir = opendir(path);
    if(dir){
        printf("Directory - OK\n");
    }
    else{
        printf("Directory NOT found\n");
        exit(-1);
    }

    closedir(dir);
    //printf("Selected Directory : %s \n" , path);

    //Add Filename to path
    strcpy(path+strlen(path), filename);
    size_t len = strlen(path)-1;
    char * filePath = (char*)malloc(len);
    memcpy(filePath, path, len);

    //Open the file
    source = fopen(filePath, "rb");
    if(source == NULL){
        fclose(source);
        free(filePath);
        printf("File not found\n");
        return true;
    }
    else{
        printf("File found\n");
        fclose(source);
        free(filePath);
        return false;
    }

}



