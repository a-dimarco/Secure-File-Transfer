#ifndef SECURE_FILE_TRANSFER_CLIENT_H
#define SECURE_FILE_TRANSFER_CLIENT_H

#include "../Utils/Socket/connection_manager.h"
#include "../Utils/Util/util.h"
using namespace std;

class client
{
public:
    client();

    explicit client(char *usernmame);

    void auth(unsigned char* nonce,EVP_PKEY * pubkey);

    void receive_list();

    void receive_packet();

    void delete_file();

    void send_clienthello();

    void server_hello_handler(unsigned char* pkt, int pos);

    // packet
    unsigned char *crt_pkt_listreq();

    unsigned char *crt_pkt_req(char *namefile, char *ext);

    unsigned char *crt_pkt_rename(char *namefile, char *ext, char *new_name, char *new_ext);

    unsigned char *crt_pkt_upload(char *file, int *size);

    unsigned char *crt_pkt_remove(char *namefile, int name_size, int *size);

    unsigned char * prepare_list_req(uint32_t* size);

    ~client();

    // andrea

    void handle_req();

    void show_menu();

    static void print_commands();

    unsigned char* crt_download_request(uint32_t* size);

    unsigned char* crt_request_pkt(char* filename, int* size, uint8_t opcode, uint16_t counter, unsigned char* shared_key);

    void rename_file();

private:
    unsigned char* nonce{};
    char *user{};
    char* file_name{};
    connection_manager cm;
    uint16_t counter{};
    unsigned char* shared_key{};
    size_t key_size{};
    unsigned char* crt_pkt_hello();
    /*char* */ void prepare_req_packet(uint8_t opcode);
    unsigned char* prepare_filename_packet(uint8_t opcode, uint32_t *size, char* file_name, char* new_name);
    void show_list(unsigned char *pkt, int pos);
    void create_downloaded_file(unsigned char* pkt);
    void handle_ack(unsigned char *pkt);
};

#endif
