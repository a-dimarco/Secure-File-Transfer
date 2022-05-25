#include "client.h"
#include <openssl/rand.h>
//#include "../Utils/Crypto/crypto.h"
#include "../Utils/Socket/connection_manager.h"

#define chello_opcode 0
#define shello_opcode 1
client::client(){};
client::client(char* username) {
    char addr[]="127.0.0.1";
    long dest_port=49151;
    
    printf("prima di memcpy");
    this->user = new char[10];
    //this->username = username;
    memcpy((void*)this->user, (void*)username, sizeof(username));
    printf("prima di costruttore");
    /*int seed=atoi(username);
    srand(seed);
    long std_port=rand()%6000+43151;
    this->cm=new connection_manager(addr,std_port);*/
    this->cm=new connection_manager(addr,8000);
    this->cm->connection(addr,dest_port);

}

char* client::send_clienthello() {
    RAND_poll();
    unsigned char nonce[8];
    RAND_bytes(nonce, 8);
    char* pkt=this->crt_pkt_hello(nonce);
    this->cm->send_packet(pkt,17);
    return this->cm->receive_packet();

}

char* client::crt_pkt_hello(unsigned char* nonce) {
    printf("hello\n");
    int pos=0;
    uint16_t us_size=htons(sizeof(user));
    uint16_t nonce_size=htons(sizeof(nonce));
    uint8_t opcode = htons(chello_opcode);
    static char pkt[17];
    memcpy(pkt, &opcode, 1);
    pos+=1;
    memcpy(pkt+pos,&us_size,2);
    pos+=2;
    memcpy(pkt+pos,&nonce_size,2);
    pos+=2;
    memcpy(pkt+pos,&this->user,10);
    pos+=10;
    memcpy(pkt+pos,&nonce,2);
    printf("%d\n",sizeof(pkt));
    return pkt;
}

void client::auth(char* pkt) {

}

client::~client(){}


