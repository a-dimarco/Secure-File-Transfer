#include "connection_manager.h"
#include <iostream>

using namespace std;
connection_manager::connection_manager() {}
connection_manager::connection_manager(int sock) {
    this->sckt = sock;
}

connection_manager::connection_manager(char* my_addr, long port) {
    int ret;
    struct sockaddr_in addr;
    this->sckt = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, my_addr, &addr.sin_addr);
    ret = bind(this->sckt, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        cerr << "Binding Error";
    
        exit(1);
    }
}

void connection_manager::connection(char* addr, long dest_port) {
    
    int ret;
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, addr, &dst_addr.sin_addr);
    ret = connect(this->sckt, (struct sockaddr *) &dst_addr, sizeof(dst_addr));
    if (ret < 0) {
        cerr << "Connection Error";
        exit(1);
    }
}

void connection_manager::listening(int queue_size) {
    int ret;
    ret = listen(this->sckt, queue_size);
    if (ret < 0) {
        cerr << "Listening Error";
        exit(1);
    }
}

int connection_manager::accepting() {
    struct sockaddr_in src_addr;
    socklen_t len;
    int sock = accept(this->sckt, (struct sockaddr *) &src_addr, &len);
    return sock;
}

void connection_manager::close_socket() {
    close(this->sckt);
}

void connection_manager::close_socket(int sock) {
    close(sock);
}

char *connection_manager::receive_packet() {
    char *pkt;
    int pkt_len;
    uint32_t pkt_len_n;
    size_t received = 0;
    ssize_t ret = 0;

    // Ricevo dimensione dei dati in ingresso
    ret=recv(this->sckt, &pkt_len_n, sizeof(pkt_len_n), 0);
    if (ret < 0) {
        cerr << "Error in receiving the size of the packet";
        exit(1);
    }
    
    pkt_len = ntohl(pkt_len_n);
    printf("ho ricevuto la size: %d\n",pkt_len);
    /*
    if (pkt_len < 0)
        cerr << "Error";
    exit(1);

    if (pkt_len == 0) {
        cerr << "Error";
        exit(1);
    }
    */
    printf("prima di allocare il buffer\n");
    // Alloco il buffer per i dati in ingresso
    pkt = new char[pkt_len];
    printf("sono qui prima di ricevere i dati\n");
    // Ricevo i dati in ingresso
    while (received < pkt_len) {
        printf("appena entrato nel ciclo receiving\n");
        ret = recv(this->sckt, pkt + received, pkt_len - received, 0);
        if (ret < 0) {
            cerr << "Error in receiving the packet";
            exit(1);
        }
        received += ret;
        printf("ho ricevuto %d bytes\n",received);
    }
    printf("ho ricevuto tutto il pacchetto\n");
    printf("pacchetto %s",pkt);
    return pkt;
}

void connection_manager::send_packet(char *packet, uint32_t pkt_len) {
    size_t sent = 0;
    printf(packet);
    ssize_t ret;
    uint32_t pkt_len_n = htonl(pkt_len);
    ret=send(this->sckt, &pkt_len_n, sizeof(pkt_len_n), 0);
    printf("size inviata %d or %d \n",pkt_len,pkt_len_n);
    while (sent < pkt_len) {
        printf("appena entrato nel ciclo sending\n");
        ret = send(this->sckt, packet + sent, pkt_len - sent, 0);
        if (ret < 0) {
            cerr << "Error in sending the packet";
            exit(1);
        }
        sent += ret;
        printf("ho inviato %d bytes\n",sent);
    }
    printf("ho inviato tutto il pacchetto\n");
}

connection_manager::~connection_manager(){}


