#include "client.h"
#include <openssl/rand.h>
//#include "../Utils/Crypto/crypto.h"
#include "../Utils/Socket/connection_manager.h"

#define chello_opcode 0
#define shello_opcode 1

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
    RAND_poll();
    unsigned char nonce[8];
    RAND_bytes(nonce, 8);
    char *pkt = this->crt_pkt_hello(nonce);
    printf("%s\n",pkt);
    this->cm->send_packet(pkt, 23);

    char * test = new char[10];//TEST -> messa per non far andare il loop il client
    cm->close_socket();//TEST
    return test;//TEST -> messa per non far andare il loop il client

    return this->cm->receive_packet();
}

char *client::crt_pkt_hello(unsigned char *nonce) {
    printf("Sono appena entrato in create packet hello\n");
    int pos = 0;
    uint16_t us_size = htons(strlen(user));
    uint16_t nonce_size = htons(sizeof(nonce));
    uint8_t opcode = htons(chello_opcode);
    static char pkt[23];
    memcpy(pkt, &opcode, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    memcpy(pkt + pos, &us_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, &nonce_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    //memcpy(pkt + pos, &this->user, 10);
    memcpy(pkt + pos, user, sizeof(user));
    pos += sizeof(user);
    memcpy(pkt + pos, nonce, 8);
    printf("Ho appena finito create packet hello\n");
    printf("pacchetto client hello: \n opcode: %d\n us_size: %d\n nonce_size: %d\n username: %s\n nonce: %s\n" ,opcode,sizeof(user), sizeof(nonce), this->user, nonce);
    return pkt;
}

void client::auth(char *pkt) {

}

client::~client() {}


