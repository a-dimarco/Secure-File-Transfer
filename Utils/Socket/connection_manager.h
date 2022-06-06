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

//--OPCODES
#define CHELLO_OPCODE 0
#define SHELLO_OPCODE 1
#define AUTH 2
#define ACK 10
#define LIST 11
#define DOWNLOAD 12
#define UPLOAD 13
#define RENAME 14
#define DELETE 15
#define LOGOUT 16
#define UPLOAD2 17
#define CHUNK 18
#define FINAL_CHUNK 19

//--PACKET SIZES
#define CLIENT_HELLO_SIZE 23
#define IVSIZE 12
#define TAGSIZE 16
#define NONCESIZE 8
#define CHUNK_SIZE 1024000 //1 Mb


//--COMMANDS
#define FILENAME 1111
#define COMMAND 2222
#define CLIENT  3333
#define SERVER  4444


using namespace std;

class connection_manager {
public:

    connection_manager();

    void send_packet(unsigned char *packet, uint32_t pkt_len);

    void close_socket();

    connection_manager(int sock);

    unsigned char *receive_packet();

    ~connection_manager();

private:

    int sckt;
};

#endif
