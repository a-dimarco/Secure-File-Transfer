#ifndef SECURE_FILE_TRANSFER_SERVER_H
#define SECURE_FILE_TRANSFER_SERVER_H
#include "../Utils/Socket/connection_manager.h"
#include "../Utils/Util/util.h"

using namespace std;

class server
{
public:
    server(int sock);

    unsigned char * prepare_list_packet(int *size);
    void handle_list(unsigned char *pkt);

    // invia pacchetto generico
    void send_packet(unsigned char *pkt);

    void receive_packet();

    void delete_file();

    void end_connection();

    // packet
    void server_hello(unsigned char* nonce);

    // pacchetto per errori, conferme e lista di file
    unsigned char *crt_pkt_string(char *s);

    // pacchetto con il file
    unsigned char *crt_pkt_downfile(char *filename);

    ~server();

    // Andrea

    void handle_req();

    string print_folder(char *path);
    
    int get_socket();

    unsigned char* prepare_renameAck_pkt(uint32_t *size, uint8_t opcode);

private:
    int socket;
    unsigned char* snonce;
    uint16_t counter;
    connection_manager cm;
    unsigned char *shared_key;
    char *file_name;
    void check_file(unsigned char *pkt, uint8_t opcode);
    EVP_PKEY *my_prvkey;
    char *logged_user; // TEST
    size_t key_size;
    void auth(unsigned char *pkt, int pos);
    void client_hello_handler(unsigned char *pkt, int pos);

    unsigned char *prepare_ack_packet(uint32_t *size, char *msg, int msg_size);
    unsigned char *prepare_ack_packet(uint32_t *size);

    unsigned char *crt_pkt_download(char *file, int *size);

    void store_file(unsigned char *pkt, uint8_t opcode);

    bool rename_file(unsigned char* pkt, int pos);

    bool file_renamer(char* new_name, char* old_name);

    void store_file(unsigned char *pkt);
};

#endif // SECURE_FILE_TRANSFER_SERVER_H