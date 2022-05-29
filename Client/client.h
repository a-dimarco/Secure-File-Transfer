#pragma once
#ifndef SECURE_FILE_TRANSFER_CLIENT_H
#define SECURE_FILE_TRANSFER_CLIENT_H

#include "../Utils/Socket/connection_manager.h"
#include "../Utils/Util/util.h"
using namespace std;

class client
{
public:
    client();

    client(char *usernmame);

    void auth(char *pkt);

    void receive_list();

    void receive_packet();

    void delete_file();

    char *send_clienthello();

    // packet
    char *crt_pkt_listreq();

    char *crt_pkt_req(char *namefile, char *ext);

    char *crt_pkt_rename(char *namefile, char *ext, char *new_name, char *new_ext);

    char *crt_pkt_upload(char *file, int *size);

    ~client();

    // andrea

    void handle_req(char *pkt);

    void show_menu();

    void print_commands();

private:
    char *user;
    connection_manager *cm;
    uint16_t counter;

    char *crt_pkt_hello(unsigned char *nonce);
    char *prepare_req_packet(uint32_t *size, uint8_t opcode);
    void show_list(char *pkt, int pos);
};

#endif
