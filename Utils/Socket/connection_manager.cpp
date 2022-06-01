#include "connection_manager.h"
#include <iostream>
#pragma once
using namespace std;

connection_manager::connection_manager() {}

connection_manager::connection_manager(int sock)
{
    this->sckt = sock;
    if(sckt < 0)
    {         
        printf("Error creating the socket\n");         
        exit(1);    
    }else{
        printf("Socket creato\n");
    }
}

connection_manager::connection_manager(char *my_addr, long port)
{
    int ret;
    struct sockaddr_in addr;
    this->sckt = socket(AF_INET, SOCK_STREAM, 0);
    if(sckt < 0)
    {         
        printf("Error creating the socket\n");         
        exit(1);    
    }
    printf("socket created\n");

    const int trueFlag = 1;
    setsockopt(this->sckt, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)); // Tells socket to reuse the connection

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, my_addr, &addr.sin_addr);
    ret = bind(this->sckt, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0)
    {
        cerr << "Binding Error\n";
        exit(1);
    }
}

void connection_manager::connection(char *addr, long dest_port)
{

    int ret;
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, addr, &dst_addr.sin_addr);
    ret = connect(this->sckt, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    if (ret < 0)
    {
        cerr << "Connection Error";
        exit(1);
    }
    printf("Connection Established\n");
}

void connection_manager::listening(int queue_size)
{
    int ret;
    ret = listen(this->sckt, queue_size);
    if (ret < 0)
    {
        cerr << "Listening Error";
        exit(1);
    }
}

int connection_manager::accepting()
{
    struct sockaddr_in src_addr;
    socklen_t len;
    int sock = accept(this->sckt, (struct sockaddr *)&src_addr, &len);
    return sock;
}

void connection_manager::close_socket()
{
    //shutdown(this->sckt,2);
    close(this->sckt);
}

void connection_manager::close_socket(int sock)
{
    //shutdown(sock,2);
    close(sock);
}

char *connection_manager::receive_packet()
{
    char *pkt;
    int pkt_len;
    uint32_t pkt_len_n;
    size_t received = 0;
    ssize_t ret = 0;
    printf("Aspetto di ricevere il paccheetto\n");
    // Ricevo dimensione dei dati in ingresso
    ret = recv(this->sckt, &pkt_len_n, sizeof(pkt_len_n), 0);
    printf("ret size: %zd\n", ret); // TEST
    if (ret < 0)
    {
        cerr << "Error in receiving the size of the packet\n";
        exit(1);
    }

    pkt_len = ntohl(pkt_len_n);
    // printf("ho ricevuto la size: %d\n", pkt_len);
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
    pkt = new char[pkt_len];
    // printf("sono qui prima di ricevere i dati\n");
    //  Ricevo i dati in ingresso
    while (received < pkt_len)
    {
        // printf("appena entrato nel ciclo receiving\n");
        ret = recv(this->sckt, pkt + received, pkt_len - received, 0);
        if (ret < 0)
        {
            cerr << "Error in receiving the packet\n";
            exit(1);
        }
        received += ret;
        printf("ho ricevuto %zu bytes\n", received);
    }
    // printf("ho ricevuto tutto il pacchetto\n");

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

void connection_manager::send_packet(char *packet, uint32_t pkt_len)
{
    size_t sent = 0;
    //printf("%s", packet);
    ssize_t ret;
    uint32_t pkt_len_n = htonl(pkt_len);
    ret = send(this->sckt, &pkt_len_n, sizeof(pkt_len_n), 0);
    if (ret < 0)
    {
        cerr << "Error in sending the packet";
        exit(1);
    }
    // printf("size inviata %d or %d \n", pkt_len, pkt_len_n);
    while (sent < pkt_len)
    {
        // printf("appena entrato nel ciclo sending\n");
        ret = send(this->sckt, packet + sent, pkt_len - sent, 0);
        if (ret < 0)
        {
            cerr << "Error in sending the packet";
            exit(1);
        }
        sent += ret;
        printf("ho inviato %zu bytes\n", sent);
    }
    // printf("ho inviato tutto il pacchetto\n");
}

connection_manager::~connection_manager(){}

//---Andrea TEST---