#include "util.h"
#include "sodium.h"
#include <sys/stat.h>
#include "sodium/randombytes.h"
#include "sodium/core.h"
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

unsigned char *crt_file_pkt(uint32_t clear_size,unsigned char* clear,uint32_t *size, uint8_t opcode, uint16_t counter, unsigned char* shared_key)
{
    if(opcode==UPLOAD){
        opcode=UPLOAD2;
    }
    int pos1 = 0;
    crypto c = crypto();
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint32_t pkt_len=aad_size + IVSIZE + clear_size + TAGSIZE;
    unsigned char* final_packet=(unsigned char*)malloc(pkt_len);
    memcpy(final_packet, &opcode, sizeof(uint8_t));
    pos1 += sizeof(uint8_t);
    uint16_t n_counter= htons(counter);
    memcpy(final_packet + pos1, &n_counter, sizeof(uint16_t));
    pos1 += sizeof(uint16_t);
    clear_size=htonl(clear_size);
    memcpy(final_packet + pos1, &clear_size, sizeof(uint32_t));
    clear_size=ntohl(clear_size);
    pos1+=sizeof(uint32_t);
    unsigned char iv[IVSIZE];
    c.create_random_iv(iv);
    unsigned char ciphertext[clear_size];
    unsigned char tag[TAGSIZE];
    c.encrypt_packet(clear, clear_size, final_packet, aad_size,shared_key , iv, IVSIZE, ciphertext, tag);
    memcpy(final_packet + pos1, iv, IVSIZE);
    pos1+= IVSIZE;
    memcpy(final_packet + pos1, ciphertext, clear_size);
    pos1 += clear_size;
    memcpy(final_packet + pos1, tag,TAGSIZE);
    *size = pkt_len;
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

bool file_opener(char *filename, char *username)
{

    char* path;
    string file_path = "server_file/client/"; // ../server_file/client/
    file_path += username;   // ../server_file/client/Alice
    
    path = &file_path[0];
    //printf("%s", path);
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
    file_path += "/file/";     // ../server_file/client/Alice/file/

    file_path += filename;     // ../server_file/client/Alice/file/filename.extension

    
    char *filepath = &file_path[0];
    printf("test: %s\n", filepath);

    // Open the file
    source = fopen(filepath, "rb");
    if (source == NULL)
    {
        printf("File not found\n");
        return false;
    }
    else
    {
        printf("File found\n");
        fclose(source);
        printf("ok\n");
        return true;
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

int send_file(char *filename, uint8_t opcode, uint16_t counter, unsigned char* shared_key, connection_manager* cm){
    int ret;
    FILE *file;
    file = fopen(filename, "rb");
    printf("filenmae %s\n",filename);
    if (file == NULL)
    {
        printf("Errore nell'apertura del file\n");
        exit(-1);
    }
    printf("prima di fseek\n");
    /*
    ret=fseek(file, 0L, SEEK_END);
    if(ret<0){
        cerr<<"fseek error";
    }
    long file_size = ftell(file);
    ret=fseek(file, 0L, SEEK_SET);
     */
    struct stat st;
    if(stat(filename, &st) != 0) {
        return 0;
    }
    size_t file_size =st.st_size;
    printf("filesize %li\n",file_size);
    if(file_size<CHUNK_SIZE){
        unsigned char clear[file_size];
        ret= fread(clear,sizeof(unsigned char),file_size,file);
        if(ret<file_size){
            cerr<<"error in reading the file";
            exit(1);
        }
        uint32_t size;
        uint32_t file_siz=(uint32_t)file_size;
        counter++;
        unsigned char* pkt= crt_file_pkt(file_siz,clear,&size,opcode, counter, shared_key);
        cm->send_packet(pkt,size);
    }else {
        opcode= CHUNK;
        uint32_t sent = 0;
        uint32_t current_len;
        uint32_t size;

        unsigned char* fragment;
            while (sent < file_size)
            {
                current_len = (file_size - sent < CHUNK_SIZE) ? file_size - sent : CHUNK_SIZE;
                if(sent+current_len==file_size){
                    opcode=FINAL_CHUNK;
                }
                printf("prima di malloc, current len %d\n",current_len);

                if(current_len==CHUNK_SIZE){
                    fragment = (unsigned char *)malloc(256000);
                }else{
                    size_t c=file_size-sent;
                    fragment = (unsigned char *)malloc(c);
                }

                //unsigned char fragment[current_len];
                fread(fragment, sizeof(unsigned char), current_len, file);
                counter++;
                printf("counter %d\n",counter);
                unsigned char* pkt= crt_file_pkt(current_len,fragment,&size,opcode, counter, shared_key);
                cm->send_packet(pkt,size);
                sent += current_len;
                //free(fragment);
            };
    }
    return counter;
}

int rcv_file(unsigned char* pkt, char *filename, uint16_t counter, unsigned char* shared_key, connection_manager* cm){
    printf("filename %s\n",filename);
    FILE *file = fopen(filename, "wb");
    if (file == nullptr) {
        printf("Errore nella fopen\n");
        exit(-1);
    }
    write_chunk(pkt, file,  counter,  shared_key);
    uint8_t opcode=CHUNK;
    unsigned char* pkto;
    while(opcode==CHUNK){
        pkto=cm->receive_packet();
        memcpy(&opcode, pkto, sizeof(opcode));
        /*
        memcpy(&count, pkto+pos, sizeof(uint16_t));
        if(count!=counter){
            cerr << "counter errato";
            exit(1);
        }*/
        counter++;
        write_chunk(pkto, file,  counter,  shared_key);

    }
    fclose(file);
    free(filename);
    return counter;
}

void write_chunk(unsigned char* pkt, FILE* file, uint16_t counter, unsigned char* shared_key){
    int ret;
    crypto c= crypto();
    int aad_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint16_t count;
    uint32_t file_size;
    int pos=sizeof(uint8_t);
    memcpy(&count, pkt+pos, sizeof(uint16_t));
    pos+=sizeof(uint16_t);
    count = ntohs(count);
    printf("count %d\n",count);
    printf("counter %d\n",counter);
    if(counter!=count){
        cerr<<"Counter errato";
        exit(0);
    }
    memcpy(&file_size, pkt+pos, sizeof(uint32_t));
    file_size = ntohl(file_size);
    pos+=sizeof(uint32_t);
    unsigned char iv[IVSIZE];
    memcpy(iv,pkt+pos,IVSIZE);
    pos+=IVSIZE;
    unsigned char ctext[file_size];
    memcpy(ctext, pkt+pos,file_size);
    pos+=file_size;
    unsigned char tag[TAGSIZE];
    memcpy(tag,pkt+pos,TAGSIZE);
    unsigned char ptext[file_size+1];
    c.decrypt_message(ctext, file_size,
                      pkt, aad_len,
                      tag,
                      shared_key,
                      iv, IVSIZE,
                      ptext);
    ptext[file_size]='\0';
    ret = fwrite(ptext, sizeof(unsigned char), file_size, file);
    if (ret < file_size) {
        printf("Errore nella fwrite\n");
        exit(-1);
    }
#pragma optimize("", off);
    memset(ptext, 0, file_size);
#pragma optimize("", on);
}




