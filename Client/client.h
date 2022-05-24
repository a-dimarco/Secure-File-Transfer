#ifndef SECURE_FILE_TRANSFER_CLIENT_H
#define SECURE_FILE_TRANSFER_CLIENT_H
#include "../Utils/Socket/connection_manager.h"

class client {
public:
    client( char* usernmame);

    void auth(char* pkt);
    void receive_list();
    void receive_packet();
    void delete_file();
    char* send_clienthello();

    //packet
    char * crt_pkt_listreq();
    char * crt_pkt_req(string namefile, string ext);
    char * crt_pkt_rename(string namefile, string ext,string new_name, string new_ext);
    char * crt_pkt_upload(char* file);

    ~client();
private:
    char* username;
    connection_manager* cm;

    char * crt_pkt_hello(unsigned char* nonce);

};


#endif