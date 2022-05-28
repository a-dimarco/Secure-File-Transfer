#include "client.h"
#include <openssl/rand.h>
#include "../Utils/Crypto/crypto.h"

using namespace std;

client::client() {};

client::client(char *username) {
    char addr[] = "127.0.0.1";
    long dest_port = 49151;
    this->user = new char[10];
    //this->username = username;
    memcpy((void *) this->user, (void *) username, sizeof(username));
    /*int seed=atoi(username);
    srand(seed);
    long std_port=rand()%6000+43151;
    this->cm=new connection_manager(addr,std_port);*/
    this->cm = new connection_manager(addr, 8000);
    this->cm->connection(addr, dest_port);

}

char *client::send_clienthello() {
    crypto *c=new crypto();
    unsigned char* nonce=c->create_nonce();
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

char *client::crt_pkt_hello(unsigned char *nonce) {//Creates first handshake packet
    //PACKET FORMAT: OPCODE - USERNAME_SIZE - NONCE_SIZE - USERNAME - NONCE
    printf("Sono appena entrato in create packet hello\n");

    uint16_t us_size = htons(strlen(user));
    uint16_t nonce_size = htons(sizeof(nonce));
    uint8_t opcode = htons(CHELLO_OPCODE);
    int pos = 0;
    static char pkt[CLIENT_HELLO_SIZE];

    memcpy(pkt, &opcode, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    memcpy(pkt + pos, &us_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, &nonce_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, user, 10);
    pos += sizeof(user);
    memcpy(pkt + pos, nonce, 8);

    /*printf("Ho appena finito create packet hello\n");
    printf("pacchetto client hello: \n opcode: %d\n us_size: %d\n nonce_size: %d\n username: %s\n nonce: %s\n" ,opcode,sizeof(user), sizeof(nonce), this->user, nonce);*/
    return pkt;
}

char *client::crt_pkt_upload(char *filename) {
    //static char pkt[23];
    int pos1 = 0;
    int ret;
    crypto *c=new crypto();
    FILE *file;
    uint8_t opcode = htons(UPLOAD);
    int aad_size=sizeof(uint8_t)+sizeof(uint16_t);
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
    memcpy(start_packet + pos1, &file_size, sizeof(uint32_t));
    unsigned char ciphertext[file_size+16];
    unsigned char tag[16];
    c->encrypt_message(file,file_size,start_packet,aad_size,c->get_key(),c->create_random_iv(), EVP_CIPHER_iv_length(EVP_aes_128_gcm()),ciphertext,tag);
    ret = fclose(file);
    if (ret != 0) {
        printf("Errore\n");
        exit(1);
    }
    char final_packet[aad_size+file_size+16+16];
    int pos = 0;
    memcpy(final_packet, start_packet, aad_size);
    pos += sizeof(aad_size);
    memcpy(final_packet, ciphertext, file_size+16);
    pos += sizeof(file_size+16);
    memcpy(final_packet, tag, 16);

    free(tag);
    free(ciphertext);
    free(start_packet);

    return final_packet;
}

void client::auth(char *pkt) {

}

client::~client() { this->cm->close_socket(); }

// Andrea Test

void client::print_commands() {
    printf("\nPlease select a command\n");
    printf("!help --> Show all available actions\n");
    printf("!list --> Show all files uploaded to the server\n");
    printf("!download --> Download a file from the server\n");
    printf("!upload --> Upload a file to the server\n");
    printf("!rename --> Rename a file stored into the server\n");
    printf("!delete --> Delete a file stored into the server\n");
    printf("!logout --> Disconnect from the server and close the application\n");
}

bool nameChecker(char *name,
                 int mode) {//Checks if file (code = FILENAME) or command (code = COMMAND) is formatted correctly - utility

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

void client::handle_req(char *pkt) {

    //Andrea test
    //Deserializzazione
    int pos = 0;
    uint8_t opcode;


    memcpy(&opcode, pkt, sizeof(opcode));//prelevo opcode
    //opcode = ntohs(opcode);
    pos+=sizeof(opcode);

    if (opcode == SHELLO_OPCODE) {
        //server_hello_handler(pkt, pos);
    } else if (opcode == ACK) {//TEST
        printf("ACK - OK\n");
        show_menu();
        return;//TEST
    } else {
        printf("Not a valid opcode\n");
        cm->close_socket();//TEST
        exit(1);//TEST
        return;
    }

    return;
}


void client::show_menu() {

    print_commands();

    char command[30];
    fgets(command, 30, stdin);

    printf("command : %s \n", command);

    if(nameChecker(command, COMMAND)){
        uint32_t size;
        if(strcmp(command, "!help\n")==0){
            show_menu();
        } else if (strcmp(command, "!help\n") == 0) {
            show_menu();
        }
        else if(strcmp(command, "!list\n")==0){
            //char * packet = prepare_ack_packet(&size);
            //printf("Test dimensione ack packet: %d\n", size);
            //cm->send_packet(packet, size);
            //close(sock);
            //exit(0);
            //char *pkt = cm->receive_packet();//waits for a request from the client
            //receive_list();//IMPLEMENT
        } else if (strcmp(command, "!download\n") == 0) {//IMPLEMENT
            show_menu();
        } else if (strcmp(command, "!upload\n") == 0) {//IMPLEMENT
            show_menu();
        } else if (strcmp(command, "!rename\n") == 0) {//IMPLEMENT
            show_menu();
        } else if (strcmp(command, "!delete\n") == 0) {//IMPLEMENT
            show_menu();
        }
        else if(strcmp(command, "!logout\n")==0){//IMPLEMENT
            char * packet = prepare_logout_packet(&size);
            printf("Test dimensione logout packet: %d\n", size);
            cm->send_packet(packet, size);
            printf("Bye!\n");
            cm->close_socket();
            exit(0);
        } else {
            printf("Command %s not found, please retry\n", command);
            show_menu();
        }
    } else {
        printf("Command format not valid, please use the format !command\n");
        show_menu();
    }
}

char* client::prepare_logout_packet(uint32_t *size){

    char * packet;
    uint8_t opcode= LOGOUT;
    *size = sizeof(opcode);
    memcpy(packet, &opcode, sizeof(opcode));

    return packet;

}