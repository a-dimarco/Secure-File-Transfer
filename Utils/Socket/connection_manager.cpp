#include "connection_manager.h"
#include <iostream>

using namespace std;

connection_manager::connection_manager(int sock) {
    this->socket = sock;
}

connection_manager::connection_manager(string my_addr, int port) {
    int ret;
    struct sockaddr_in addr;
    this->socket = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, my_addr, &addr.sin_addr);
    ret = bind(this->socket, (struct sockaddr *) &addr, sizeof(addr));
    if (ret != 1) {
        cerr << "Binding Error";
        exit(1);
    }
}

void connection_manager::connection(string addr, long dest_port) {
    int ret;
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, addr, &dst_addr.sin_addr);
    if (ret != 1) {
        cerr << "Binding Error";
        exit(1);
    }
    ret = connect(this->socket, (struct sockaddr *) &dst_addr, sizeof(dst_addr));
    if (ret != 1) {
        cerr << "Connection Error";
        exit(1);
    }
}

void connection_manager::listening(int queue_size) {
    int ret;
    ret = listen(this->socket, queue_size);
    if (ret != 1) {
        cerr << "Connection Error";
        exit(1);
    }
}

int connection_manager::accepting() {
    struct sockaddr_in src_addr;
    int len;
    int sock = accept(this->socket, (struct sockaddr *) &src_addr, &len);
    return sock;
}

void connection_manager::close_socket() {
    close(this->socket);
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
    if (recv(this->socket, &pkt_len_n, sizeof(pkt_len_n), 0) <= 0) {
        cerr << "Error in receiving the packet";
        exit(1);
    }
    pkt_len = ntohl(pkt_len_n);
    if (pkt_len < 0)
        cerr << "Error";
    exit(1);

    if (pkt_len == 0) {
        cerr << "Error";
        exit(1);
    }

    // Alloco il buffer per i dati in ingresso
    pkt = new char[pkt_len];
    if (pkt == NULL) {
        cerr << "Error in receiving the packet";
        exit(1);
    }

    // Ricevo i dati in ingresso
    while (received < pkt_len) {
        ret = recv(this->socket, pkt + received, pkt_len - received, 0);
        if (ret < 0) {
            cerr << "Error in receiving the packet";
            exit(1);
        }
        if (ret == 0) {
            cerr << "Error in receiving the packet";
            exit(1);
        }
        received += ret;
    }
    return 0;
}

void connection_manager::send_packet(char *packet) {
    size_t sent = 0;
    ssize_t ret;
    int pkt_len = sizeof(packet);
    uint32_t pkt_len_n = htonl(pkt_len);
    send(this->socket, &pkt_len_n, sizeof(pkt_len_n), 0);
    while (sent < pkt_len) {
        ret = send(this->socket, packet + sent, pkt_len - sent, 0);
        if (ret < 0) {
            cerr << "Error in sending the packet";
            exit(1);
        }
        sent += ret;
    }
}
