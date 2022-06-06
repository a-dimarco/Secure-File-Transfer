#include "connection_manager.h"
#include <iostream>

using namespace std;

connection_manager::connection_manager() {}

connection_manager::connection_manager(int sock) {
    this->sckt = sock;
    if (sckt < 0) {
        printf("Error creating the socket\n");
        exit(1);
    }
}

void connection_manager::close_socket() {
    close(this->sckt);
}

unsigned char *connection_manager::receive_packet() {
    unsigned char *pkt;
    uint32_t pkt_len;
    uint32_t pkt_len_n;
    uint32_t received = 0;
    ssize_t ret;

    // Ricevo dimensione dei dati in ingresso
    ret = recv(this->sckt, &pkt_len_n, sizeof(pkt_len_n), 0);

    if (ret < 0) {
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
    pkt = (unsigned char *) malloc(pkt_len + 1);
    if(pkt==NULL){
        cerr << "Malloc return NULL";
        exit(1);
    }
    while (received < pkt_len) { ;
        ret = recv(this->sckt, pkt + received, pkt_len - received, 0);
        if (ret <= 0) {
            cerr << "Error in receiving the packet\n";
            exit(1);
        }
        received += ret;
    }
    printf("ho ricevuto tutto il pacchetto %u bytes\n", received);

    return pkt;
}

void connection_manager::send_packet(unsigned char *packet, uint32_t pkt_len) {
    uint32_t sent = 0;
    ssize_t ret;
    pkt_len = htonl(pkt_len);
    ret = send(this->sckt, &pkt_len, sizeof(pkt_len), 0);
    if (ret < 0) {
        cerr << "Error in sending the size";
        exit(1);
    }
    pkt_len = ntohl(pkt_len);
    printf("size inviata %d bytes \n", pkt_len);
    while (sent < pkt_len) {

        ret = send(this->sckt, packet + sent, pkt_len - sent, 0);
        if (ret < 0) {
            cerr << "Error in sending the packet";
            exit(1);
        }
        sent += ret;
    }

    free(packet);
    printf("ho inviato tutto il pacchetto %u\n", sent);
}


connection_manager::~connection_manager() {}

