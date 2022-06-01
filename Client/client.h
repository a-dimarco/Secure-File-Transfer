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

    void auth(unsigned char* nonce,EVP_PKEY * pubkey);

    void receive_list();

    void receive_packet();

    void delete_file();

    char *send_clienthello();

    void server_hello_handler(char* pkt, int pos);

    // packet
    char *crt_pkt_listreq();

    char *crt_pkt_req(char *namefile, char *ext);

    char *crt_pkt_rename(char *namefile, char *ext, char *new_name, char *new_ext);

    char *crt_pkt_upload(char *file, int *size);

    char *crt_pkt_remove(char *namefile, int name_size, uint32_t *size);

    ~client();

    // andrea

    void handle_req(char *pkt);

    void show_menu();

    void print_commands();
    
    char* crt_download_request(uint32_t* size);
    
    char* crt_request_pkt(char* filename, int* size, uint8_t opcode, uint16_t counter, unsigned char* shared_key);

    void rename_file();

private:
    unsigned char nonce[8];
    char *user;
    char* file_name;
    connection_manager *cm;
    uint16_t counter;
    unsigned char* shared_key;
    size_t* key_size;
    char* crt_pkt_hello(unsigned char *nonce);
    char* prepare_req_packet(uint32_t *size, uint8_t opcode);
    char* prepare_filename_packet(uint8_t opcode, uint32_t *size, char* file_name, char* new_name);
    void show_list(char *pkt, int pos);
    void create_downloaded_file(char* pkt);
    void handle_ack(char *pkt,uint8_t opcode);
};

#endif
