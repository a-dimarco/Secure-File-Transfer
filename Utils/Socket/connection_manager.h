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
#define RENAME_ACK 17
#define RENAME_NACK 18

//--PACKET SIZES
#define CLIENT_HELLO_SIZE 23
#define IVSIZE 12
#define TAGSIZE 16
#define NONCESIZE 8
#define CHUNK_SIZE 512000 // 512 KiB

//--FILE PATHS
#define SERVER_PATH "server_file/client/"
#define CLIENT_PATH "client_folders/"

//--COMMANDS
#define FILENAME 1111
#define COMMAND 2222
#define CLIENT  3333
#define SERVER  4444


using namespace std;

class connection_manager
{
public:
    connection_manager();

    void send_packet(unsigned char *packet, uint32_t pkt_len);

    void listening(int queue_size);

    int accepting();

    void close_socket();

    void close_socket(int sock);

    connection_manager(char *addr, long port);

    connection_manager(int sock);

    void connection(char *addr, long port);

    unsigned char *receive_packet();

    ~connection_manager();

    // Andrea

    // uint8_t receive_opcode();

private:
    int sckt;
};

#endif // SECURE_FILE_TRANSFER_CONNECTION_MANAGER_H
