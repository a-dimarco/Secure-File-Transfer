#pragma once
#include "client.h"
#include <openssl/rand.h>
#include "../Utils/Crypto/crypto.h"

using namespace std;

client::client(){};

client::client(char *username)
{
    char addr[] = "127.0.0.1";
    // long dest_port = 49151;
    long dest_port = 8080;
    this->user = new char[10];
    // this->username = username;
    memcpy((void *)this->user, (void *)username, sizeof(username));
    /*int seed=atoi(username);
    srand(seed);
    long std_port=rand()%6000+43151;
    this->cm=new connection_manager(addr,std_port);*/

    this->cm = new connection_manager(addr, 8000);
    this->cm->connection(addr, dest_port);
    this->counter = 0;
}

char *client::send_clienthello()
{
    crypto *c = new crypto();

    // unsigned char* nonce=c->create_nonce();
    RAND_poll();
    unsigned char nonce[8];
    RAND_bytes(nonce, 8);

    printf("checkpoint\n");
    char *pkt = this->crt_pkt_hello(nonce);
    printf("%s\n", pkt);
    this->cm->send_packet(pkt, 23);
    /*if(this->cm->receive_ack()){
        char * test = new char[10];//TEST -> messa per non far andare il loop il client
        //cm->close_socket();//TEST
        return test;//TEST -> messa per non far andare il loop il client
    }*/

    return this->cm->receive_packet();
}

char *client::crt_pkt_hello(unsigned char *nonce)
{ // Creates first handshake packet
    // PACKET FORMAT: OPCODE - USERNAME_SIZE - NONCE_SIZE - USERNAME - NONCE
    printf("Sono appena entrato in create packet hello\n");

    uint16_t us_size = htons(strlen(user) + 1);
    uint16_t nonce_size = htons(sizeof(nonce) + 1);
    uint8_t opcode = htons(CHELLO_OPCODE);
    int pos = 0;
    static char pkt[CLIENT_HELLO_SIZE];

    memcpy(pkt, &opcode, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    memcpy(pkt + pos, &us_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, &nonce_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, user, sizeof(user));
    // pos += sizeof(user);
    pos += strlen(user) + 1;
    memcpy(pkt + pos, nonce, 8);

    // printf("Ho appena finito create packet hello\n");
    printf("pacchetto client hello: \n opcode: %d\n us_size: %d\n nonce_size: %d\n username: %s\n nonce: %s\n", opcode, us_size, nonce_size, this->user, nonce);
    return pkt;
}

char *client::crt_pkt_upload(char *filename, int *size)
{

    char *pkt = crt_file_pkt(filename, size, UPLOAD, this->counter);
    this->counter++;
    return pkt;
    // static char pkt[23];
    /* int pos1 = 0;
     int ret;
     crypto *c=new crypto();
     FILE *file;
     uint8_t opcode = htons(UPLOAD);
     int aad_size=sizeof(uint8_t)+sizeof(uint16_t)+sizeof(uint32_t);
     unsigned char start_packet[aad_size];

     file = fopen(filename, "rb");
     if (file == NULL) {
         printf("Errore nell'apertura del file\n");
         exit(-1);
     }
     fseek(file, 0L, SEEK_END);
     uint32_t file_size = ftell(file);
     fseek(file, 0L, SEEK_SET);
     memcpy(start_packet, &opcode, sizeof(uint8_t));
     pos1 += sizeof(uint8_t);
     memcpy(start_packet + pos1, &this.counter, sizeof(uint16_t));
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
     char final_packet[aad_size+iv_size+file_size+16+16];
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
     return final_packet;*/
}

void client::auth(char *pkt)
{
}

client::~client() { this->cm->close_socket(); }

// Andrea Test

void client::print_commands()
{
    printf("\nPlease select a command\n");
    printf("!help --> Show all available actions\n");
    printf("!list --> Show all files uploaded to the server\n");
    printf("!download --> Download a file from the server\n");
    printf("!upload --> Upload a file to the server\n");
    printf("!rename --> Rename a file stored into the server\n");
    printf("!delete --> Delete a file stored into the server\n");
    printf("!logout --> Disconnect from the server and close the application\n");
}

void client::handle_req(char *pkt)
{

    // Andrea test
    // Deserializzazione
    int pos = 0;
    uint8_t opcode;

    memcpy(&opcode, pkt, sizeof(opcode)); // prelevo opcode
    // opcode = ntohs(opcode);
    pos += sizeof(opcode);

    if (opcode == SHELLO_OPCODE)
    {
        // server_hello_handler(pkt, pos);
    }
    else if (opcode == LIST)
    {
        printf("Received List\n");
        show_list(pkt, pos);
        show_menu();
    }
    else if (opcode == ACK)
    { // TEST
        printf("ACK - OK\n");
        show_menu();
        return; // TEST
    }
    else if (opcode == DOWNLOAD) {
    	create_downloaded_file(pkt);
    }
    else
    {
        printf("Not a valid opcode\n");
        cm->close_socket(); // TEST
        exit(1);            // TEST
        return;
    }

    return;
}

void client::show_menu()
{

    print_commands();

    char command[30];
    fgets(command, 30, stdin);

    printf("command : %s \n", command);

    if (nameChecker(command, COMMAND))
    {
        uint32_t size;
        if (strcmp(command, "!help\n") == 0)
        {
            show_menu();
        }
        else if (strcmp(command, "!list\n") == 0)
        {
            char *packet = prepare_req_packet(&size, LIST);
            // printf("Test dimensione list packet: %d\n", size);
            cm->send_packet(packet, size);
            char *pkt = cm->receive_packet(); // waits for the list packet
            handle_req(pkt);
        }
        else if (strcmp(command, "!download\n") == 0)
        { // IMPLEMENT
            char* req = crt_download_request(&size);
            cm->send_packet(req, size);
            char *pkt = cm->receive_packet();
            handle_req(pkt);
            show_menu();
        }
        else if (strcmp(command, "!upload\n") == 0)
        { // IMPLEMENT
            show_menu();
        }
        else if (strcmp(command, "!rename\n") == 0)
        { // IMPLEMENT
            show_menu();
        }
        else if (strcmp(command, "!delete\n") == 0)
        {
            char namefile[]="a.txt";
            uint32_t *size;
            char *pkt= crt_pkt_remove(namefile,sizeof(namefile),size);
            this->cm->send_packet(pkt,*size);
            char *packet = cm->receive_packet();
            handle_req(packet);
            show_menu();
        }
        else if (strcmp(command, "!logout\n") == 0)
        { // IMPLEMENT
            char *packet = prepare_req_packet(&size, LOGOUT);
            cm->send_packet(packet, size);
            printf("Bye!\n");
            cm->close_socket();
            exit(0);
        }
        else
        {
            printf("Command %s not found, please retry\n", command);
            show_menu();
        }
    }
    else
    {
        printf("Command format not valid, please use the format !command\n");
        show_menu();
    }
}

char *client::prepare_req_packet(uint32_t *size, uint8_t opcode)
{

    // opcode = htons(opcode);

    char *packet;
    *size = sizeof(opcode);
    memcpy(packet, &opcode, sizeof(uint8_t));
    printf("request packet codice:%d ha size %d", opcode, *size);
    return packet;
}

void client::show_list(char *pkt, int pos)
{

    uint16_t list_size;

    // Deserializzazione

    printf("Checkpoint1\n");

    memcpy(&list_size, pkt + pos, sizeof(list_size)); // prelevo list_size inizializzo la variabile che dovrà contenerlo
    pos += sizeof(list_size);
    printf("Checkpoint2\n");
    list_size = ntohs(list_size);
    char content[list_size];
    // char* content /*= &temp[0]*/;

    // memcpy(&content, pkt+pos, list_size);//prelevo la lista
    strcpy(content, pkt + pos);

    // Fine Deserializzazione
    printf("Checkpoint3: %d\n", list_size);

    printf("Available files:\n%s", content);

    show_menu();
}


char * client::crt_pkt_remove(char *namefile, int name_size, uint32_t *size){
    int pos = 0;
    uint8_t opcode = DELETE;
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    int pkt_len = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t) + name_size + 16;
    char packet[pkt_len];
    *size = pkt_len;
    memcpy(packet, &opcode, sizeof(opcode));
    pos += sizeof(opcode);
    this->counter++;
    memcpy(packet + pos, &counter, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    uint16_t size_m = htons(name_size);
    memcpy(packet + pos, &size_m, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    crypto *c = new crypto();
    unsigned char *iv = c->create_random_iv();
    memcpy(packet + pos, iv, iv_size);
    pos += iv_size;
    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char ct[name_size + 16];
    unsigned char tag[16];
    c->encrypt_packet((unsigned char *)namefile, name_size, (unsigned char *)packet, aad_size, this->shared_key, iv, iv_size, ct, tag);
    memcpy(packet+pos,ct,name_size+16);
    pos+=name_size+16;
    memcpy(packet+pos,tag,16);
    return packet;
}

char* client::crt_download_request(uint32_t* size) {
	printf("Inserisci file\n");
	char filename[31];
	fgets(filename, 31, stdin);

	for (int i=0; i<31;i++)
		if (filename[i] == '\n') {
			filename[i] = '\0';
			break;
		}
		
	bool check = nameChecker(filename, FILENAME);
	if (!check) {
		printf("Inserisci un nome corretto\n");
		return NULL;
	}
	this->file_name = filename;
	this->counter++;
	char* packet = crt_request_pkt(filename, (int*)size, DOWNLOAD, this->counter, this->shared_key);
	return packet;
}

char* client::crt_request_pkt(char* filename, int* size, uint8_t opcode, uint16_t counter, unsigned char* shared_key) {

	crypto* c = new crypto();
	
	int aad_size = sizeof(uint8_t)+sizeof(uint16_t)*2;
	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
	uint16_t ptext_size = htons(strlen(filename) + 1);
	int pos = 0;
	int cipherlen;
	uint16_t n_counter = htons(counter);
	*size = aad_size+iv_size+ptext_size+2*16;
	
	char* pkt = (char*)malloc(*size);
	unsigned char* iv = c->create_random_iv();
	unsigned char* tag = (unsigned char*)malloc(16);
	//unsigned char* ciphertext = (unsigned char*)malloc(ptext_size+16);
	
	memcpy(pkt, &opcode, sizeof(uint8_t));
	pos += sizeof(uint8_t);
	memcpy(pkt+pos, &n_counter, sizeof(uint16_t));
	pos += sizeof(uint16_t);
	memcpy(pkt+pos, &ptext_size, sizeof(uint16_t));
	pos += sizeof(uint16_t);
	memcpy(pkt+pos, iv, iv_size);
	pos += iv_size;
	 
	
	cipherlen = c->encrypt_packet((unsigned char*)filename, strlen(filename)+1,
                           (unsigned char*)pkt, aad_size, shared_key, iv, iv_size,
                           (unsigned char*)pkt+pos, tag);
        
        pos += cipherlen;
        memcpy(pkt+pos, tag, 16);
        return pkt;  
}

void client::create_downloaded_file(char* pkt) {

	int ret;
		
	crypto* c = new crypto();
	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
	int aad_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
	
	char* counter_pos = pkt + sizeof(uint8_t);
	char* size_pos = counter_pos + sizeof(uint16_t);
	char* iv_pos = size_pos + sizeof(uint32_t);
	char* ct_pos = iv_pos + iv_size;
	
	uint16_t h_counter;
	uint32_t h_size;
	
	memcpy(&h_counter, counter_pos, sizeof(uint16_t));
	h_counter = ntohs(h_counter);
	memcpy(&h_size, size_pos, sizeof(uint32_t));
	h_size = ntohl(h_size);
	
	int ct_len = h_size + (16 - h_size%16);
    	if (h_size % 16 == 0)
    		ct_len += 16;
    		
    	char* tag_pos = ct_pos + ct_len;
    	
    	unsigned char* ptext = (unsigned char*)malloc(h_size);
    	
    	c->decrypt_message((unsigned char*)ct_pos, ct_len,
                            (unsigned char*)pkt, aad_len,
                            (unsigned char*)tag_pos,
                            this->shared_key,
                            (unsigned char*)iv_pos, iv_size,
                            ptext);
                            
       FILE* file = fopen(this->file_name, "wb");
       if (file == NULL) {
       	printf("Errore nella fopen\n");
       	exit(-1);
       }                     
	
	ret = fwrite(ptext, sizeof(unsigned char), h_size, file);
	if (ret < h_size) {
		printf("Errore nella fwrite\n");
		exit(-1);
	}
	ret = fclose(file);
	
	#pragma optimize("", off);
        memset(ptext, 0, h_size);
	#pragma optimize("", on);
	
	free(ptext);
		
}

