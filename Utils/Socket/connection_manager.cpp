#include "connection_manager.h"
#include <iostream>
#include "../Util/util.h"

using namespace std;

connection_manager::connection_manager() {}

/* Creates a connection manager object storing the socket */
connection_manager::connection_manager(int sock) {
    this->sckt = sock;
    if (sckt < 0) {
        printf("Error creating the socket\n");
        exit(1);
    }
}

/* Closes a given socket */
void connection_manager::close_socket() {
    close(this->sckt);
}

/* Receives an entire packet */
unsigned char *connection_manager::receive_packet() {

    unsigned char *pkt;
    uint32_t pkt_len;
    uint32_t pkt_len_n;
    uint32_t received = 0;
    ssize_t ret;

    /* Firstly there is the receiving of the packet size */
    ret = recv(this->sckt, &pkt_len_n, sizeof(pkt_len_n), 0);
    if (ret < 0) {
        throw Exception("Error in receiving the size of the packet\n");
    }

    pkt_len = ntohl(pkt_len_n);
    if (pkt_len <= 0) {
        throw Exception("Packet len <= 0");
    }

    pkt = (unsigned char *) malloc(pkt_len);
    if (pkt == NULL) {
        throw Exception("Error in receiving the size of the packet\n");
    }

    /* Receives and store all the packet */
    while (received < pkt_len) { ;

        ret = recv(this->sckt, pkt + received, pkt_len - received, 0);
        if (ret <= 0) {
            throw Exception("Error in receiving the packet\n");
        }

        received += ret;
    }

    return pkt;
}

/* Sends a packet */
void connection_manager::send_packet(unsigned char *packet, uint32_t pkt_len) {

    uint32_t sent = 0;
    ssize_t ret;
    pkt_len = htonl(pkt_len);

    /* Firstly it sends the size of the packet */
    ret = send(this->sckt, &pkt_len, sizeof(pkt_len), 0);
    if (ret < 0) {
        throw Exception("Error in sending the size of the packet\n");
    }

    pkt_len = ntohl(pkt_len);

    /* Sends all the packet */
    while (sent < pkt_len) {

        ret = send(this->sckt, packet + sent, pkt_len - sent, 0);
        if (ret < 0) {
            throw Exception("Error in sending the packet\n");
        }

        sent += ret;
    }

    /* Packet clean up */
    free(packet);

}


connection_manager::~connection_manager() {}

