#include "connection_manager.h"
#include <iostream>
using namespace std;

connection_manager::connection_manager() {}

connection_manager::connection_manager(int sock)
{
    this->sckt = sock;
    if(sckt < 0)
    {         
        printf("Error creating the socket\n");         
        exit(1);    
    }
}
void connection_manager::close_socket()
{;
    close(this->sckt);
}

unsigned char *connection_manager::receive_packet()
{
    unsigned char *pkt;
    int pkt_len;
    uint32_t pkt_len_n;
    uint32_t received = 0;
    ssize_t ret;

    // Ricevo dimensione dei dati in ingresso
    ret = recv(this->sckt, &pkt_len_n, sizeof(pkt_len_n), 0);

    if (ret < 0)
    {
        cerr << "Error in receiving the size of the packet\n";
        exit(1);
    }
    pkt_len = ntohl(pkt_len_n);
    printf("ho ricevuto la size: %d\n", pkt_len);
    /*
    if (pkt_len < 0)
        cerr << "Error";
    exit(1);
    if (pkt_len == 0) {
        cerr << "Error";
        exit(1);
    }
    */
    // printf("prima di allocare il buffer\n");
    //  Alloco il buffer per i dati in ingresso
    pkt = (unsigned char*)malloc(pkt_len+1);
    // printf("sono qui prima di ricevere i dati\n");
    //  Ricevo i dati in ingresso
    while (received < pkt_len)
    {
        // printf("appena entrato nel ciclo receiving\n");
        ret = recv(this->sckt, pkt + received, pkt_len - received, 0);
        if (ret <= 0)
        {
            cerr << "Error in receiving the packet\n";
            exit(1);
        }
        received += ret;
        //printf("ho ricevuto %zu bytes\n", received);
    }
    printf("ho ricevuto tutto il pacchetto %u bytes\n", received);

    /*
        //Deserializzazione
        int pos = 0;
        uint16_t us_size;
        uint16_t nonce_size;
        uint8_t opcode;
        memcpy(&opcode, pkt, sizeof(opcode));//prelevo opcode
        opcode = ntohs(opcode);
        pos+=sizeof(opcode);
        memcpy(&us_size, pkt+pos, sizeof(us_size)); //prelevo us_size inizializzo la variabile che dovrà contenerlo
        pos+=sizeof(us_size);
        us_size = ntohs(us_size);
        char username[us_size];
        memcpy(&nonce_size, pkt+pos, sizeof(nonce_size)); //prelevo nonce_size e inizializzo la variabile che dovrà contenerlo
        pos+=sizeof(nonce_size);
        nonce_size = ntohs(nonce_size);
        unsigned char nonce[nonce_size];
        memcpy(&username, pkt+pos, us_size);//prelevo l'username
        pos+=us_size;
        memcpy(&nonce, pkt+pos, nonce_size);//prelevo il nonce
        //Fine Deserializzazione
        //printf("pacchetto: \n opcode: %d\n us_size: %d\n nonce_size: %d\n, username: %s\n nonce: %s\n" ,opcode,us_size, nonce_size, username, nonce);
        //test andrea
        return username;
        //test andrea
    */
    return pkt;
}

void connection_manager::send_packet(unsigned char *packet, uint32_t pkt_len)
{
    uint32_t sent = 0;
    ssize_t ret;
    pkt_len = htonl(pkt_len);
    ret = send(this->sckt, &pkt_len, sizeof(pkt_len), 0);
    if (ret < 0)
    {
        cerr << "Error in sending the size";
        exit(1);
    }
    pkt_len=ntohl(pkt_len);
    printf("size inviata %d bytes \n", pkt_len);
    while (sent < pkt_len)
    {
        // printf("appena entrato nel ciclo sending\n");
        ret = send(this->sckt, packet + sent, pkt_len - sent, 0);
        if (ret < 0)
        {
            cerr << "Error in sending the packet";
            //printf("ret %d\n",ret);
            exit(1);
        }
        sent += ret;
    }
    
    free(packet);
    printf("ho inviato tutto il pacchetto %u\n", sent);
}


connection_manager::~connection_manager(){}

//---Andrea TEST---
