#ifndef SECURE_FILE_TRANSFER_CONNECTION_MANAGER_H
#define SECURE_FILE_TRANSFER_CONNECTION_MANAGER_H
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>

using namespace std;

class connection_manager {
public:
    connection_manager();
    void send_packet(char* packet, uint32_t pkt_len);
    void listening(int queue_size);
    int accepting();
    void close_socket();
    void close_socket(int sock);
    connection_manager(char* addr, long port);
    connection_manager(int sock);
    void connection(char* addr, long port);
    char* receive_packet();
    ~connection_manager();

private:
    
    int sckt;
};


#endif //SECURE_FILE_TRANSFER_CONNECTION_MANAGER_H
