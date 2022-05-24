#ifndef SECURE_FILE_TRANSFER_CONNECTION_MANAGER_H
#define SECURE_FILE_TRANSFER_CONNECTION_MANAGER_H
#include "connection_manager.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <string>
#include <string.h>
#include <winsock.h>
using namespace std;
class connection_manager {
public:
    void send_packet(char* packet);
    void listening(int queue_size);
    int accepting();
    void close_socket();
    void close_socket(int sock);
    connection_manager(string addr,int port);
    connection_manager(int sock);
    void connection(string addr, long port);
    char* receive_packet();
    ~connection_manager();

private:
    int socket;
};


#endif //SECURE_FILE_TRANSFER_CONNECTION_MANAGER_H
