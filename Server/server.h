#ifndef SECURE_FILE_TRANSFER_SERVER_H
#define SECURE_FILE_TRANSFER_SERVER_H
#include "../Utils/Socket/connection_manager.h"
#include "../Utils/Util/util.h"

using namespace std;

class server
{
public:
    server(int sock);

    void send_list();

    // invia pacchetto generico
    void send_packet(const char *pkt);

    void receive_packet();

    void delete_file();

    void auth();

    void end_connection();

    // packet
    void server_hello(unsigned char* nonce);

    // pacchetto per errori, conferme e lista di file
    const char *crt_pkt_string(char *s);

    // pacchetto con il file
    const char *crt_pkt_downfile(char *filename);

    ~server();

    // Andrea

    void handle_req();

    string print_folder(char *path);
    
    int get_socket();

private:
    int socket;
    unsigned char* snonce;
    uint16_t counter;
    connection_manager *cm;
    unsigned char *shared_key;
    char *file_name;
    void check_file(char *pkt, uint8_t opcode);
    EVP_PKEY *my_prvkey;
    char *logged_user; // TEST

    void client_hello_handler(char *pkt, int pos);

    char *prepare_ack_packet(uint32_t *size, char *msg, int msg_size);
    char *prepare_ack_packet(uint32_t *size);

    char *crt_pkt_download(char *file, int *size);

    void store_file(char *pkt, uint8_t opcode);

    bool rename_file(char* pkt, int pos);

    bool file_renamer(char* new_name, char* old_name);

    void store_file(char *pkt);
};

#endif // SECURE_FILE_TRANSFER_SERVER_H
