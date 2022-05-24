#ifndef SECURE_FILE_TRANSFER_SERVER_H
#define SECURE_FILE_TRANSFER_SERVER_H
#include <string.h>
#include <string>

using namespace std;

class server {
public:
    server();

    void show_list();
    //invia pacchetto generico
    void send_packet(const char* pkt);
    void receive_packet();
    void delete_file();
    void auth();
    void end_connection();

    //packet
    void server_hello(int nonce);
    //pacchetto per errori, conferme e lista di file
    const char* crt_pkt_string(string s);
    //pacchetto con il file
    const char* crt_pkt_downfile(string filename);

    ~server();
private:


};


#endif //SECURE_FILE_TRANSFER_SERVER_H
