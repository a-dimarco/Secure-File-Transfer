#include "client.h"
#include <openssl/rand.h>
#include "../Utils/Crypto/crypto.h"
#include "../Utils/Socket/connection_manager.h"

#define chello_opcode 0
#define shello_opcode 1

client::client( char* username) {
    string addr="127.0.0.1";
    long dest_port=49151;
    this->username=username;
    int seed=atoi(username);
    srand(seed);
    long std_port=rand()%6000+43151;
    this->cm=new connection_manager(addr,std_port);
    this->cm->connection(addr,dest_port);

}

char* client::send_clienthello() {
    RAND_poll();
    unsigned char nonce[8];
    RAND_bytes(nonce, 8);
    char* pkt=this->crt_pkt_hello(nonce);
    this->cm->send_packet(pkt);
    return this->cm->receive_packet();

}

char* client::crt_pkt_hello(unsigned char* nonce) {
    int pos=0;
    uint16_t us_size=htons(10);
    uint16_t nonce_size=htons(8);
    char * pkt;
    uint8_t opcode = htons(chello_opcode);
    memcpy(pkt, &opcode, sizeof(opcode));
    pos+=sizeof(opcode);
    memcpy(pkt+pos,&us_size,sizeof(uint16_t));
    pos+=sizeof(uint16_t);
    memcpy(pkt+pos,&nonce_size,sizeof(uint16_t));
    pos+=sizeof(uint16_t);
    memcpy(pkt+pos,&this->username,10);
    pos+=sizeof(10);
    memcpy(pkt+pos,&nonce,10);
    return pkt;
}

void client::auth(char* pkt) {

}


