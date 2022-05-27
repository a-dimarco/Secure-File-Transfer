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
#include <regex>

using namespace std;

//--OPCODES
#define CHELLO_OPCODE 0 
#define SHELLO_OPCODE 1
#define ACK           10
#define LIST          11
#define DOWNLOAD      12
#define UPLOAD        13
#define RENAME        14
#define DELETE        15
#define LOGOUT        16

//--PACKET SIZES
#define CLIENT_HELLO_SIZE 23
#define CHUNK_SIZE 512000 //512 KiB

//--FILE PATHS
#define SERVER_PATH "../server_files/"
#define CLIENT_PATH "../client_folders/"

//--COMMANDS
#define FILENAME 1111
#define COMMAND  2222


class connection_manager {
public:
    connection_manager();

    void send_packet(char *packet, uint32_t pkt_len);

    void listening(int queue_size);

    int accepting();

    void close_socket();

    void close_socket(int sock);

    connection_manager(char *addr, long port);

    connection_manager(int sock);

    void connection(char *addr, long port);

    char *receive_packet();

    ~connection_manager();

    //Andrea

    //bool receive_ack();
    //void send_ack();
    uint8_t receive_opcode();
    void send_opcode(uint8_t opcode);

private:

    int sckt;
};


#endif //SECURE_FILE_TRANSFER_CONNECTION_MANAGER_H
