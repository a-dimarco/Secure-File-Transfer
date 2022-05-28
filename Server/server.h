#ifndef SECURE_FILE_TRANSFER_SERVER_H
#define SECURE_FILE_TRANSFER_SERVER_H

#include "../Utils/Socket/connection_manager.h"
#include "../Utils/Util/util.cpp"

using namespace std;

class server {
public:
    server(int sock);

    void send_list();

    //invia pacchetto generico
    void send_packet(const char *pkt);

    void receive_packet();

    void delete_file();

    void auth();

    void end_connection();

    //packet
    void server_hello(int nonce);

    //pacchetto per errori, conferme e lista di file
    const char *crt_pkt_string(char *s);

    //pacchetto con il file
    const char *crt_pkt_downfile(char *filename);

    ~server();

    //Andrea

    void handle_req();

private:

    int socket;
    uint16_t counter;
    connection_manager *cm;
    char* logged_user;//TEST

    void client_hello_handler(char *pkt, int pos);

    char *prepare_ack_packet(uint32_t *size);
    
    char *crt_pkt_download(char *file, int* size);

};


#endif //SECURE_FILE_TRANSFER_SERVER_H
