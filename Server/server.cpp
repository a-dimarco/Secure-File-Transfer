#include "server.h"
using namespace std;

server::server(int sock) {
    this->socket = sock;
    this->cm = new connection_manager(this->socket);
    this->counter = 0;
}

/*void server::handle_req() {//TEST deserializza e gestisce il 1° packet dell'handshake con il server

    char *pkt = cm->receive_packet();

    //Andrea test
    //Deserializzazione
    int pos = 0;
    uint16_t us_size;
    uint16_t nonce_size;
    uint8_t opcode;

    
    memcpy(&opcode, pkt, sizeof(opcode));//prelevo opcode
    opcode = ntohs(opcode);
    pos+=sizeof(opcode);

    memcpy(&us_size, pkt+pos, sizeof(us_size)); //prelevo us_size inizializzo la variabile che dovrà contenerlo
    pos+=sizeof(us_size);
    us_size = ntohs(us_size);
    char username[us_size];

    memcpy(&nonce_size, pkt+pos, sizeof(nonce_size)); //prelevo nonce_size e inizializzo la variabile che dovrà contenerlo
    pos+=sizeof(nonce_size);
    nonce_size = ntohs(nonce_size);
    unsigned char nonce[nonce_size];

    memcpy(&username, pkt+pos, us_size);//prelevo l'username
    pos+=us_size;

    memcpy(&nonce, pkt+pos, nonce_size);//prelevo il nonce

    //Fine Deserializzazione

    printf("pacchetto: \n opcode: %d\n us_size: %d\n nonce_size: %d\n, username: %s\n nonce: %s\n" ,opcode,us_size, nonce_size, username, nonce);

    //test andrea
    printf("username ricevuto %s\n", username);
    char test[us_size];
    strcpy(test, username);

    if (strcmp(username, test) == 0){//username usato per testing metodi
        printf("Username - OK\n");
        cm->send_opcode(ACK);
        //close(sock);
        //exit(0);
        char *pkt = cm->receive_packet();//waits for a request from the client
        //chiama metodo con while true che si blocca in receive packet fino a che non ha ricevuto opcode logout
    }
    else{
        printf("Username - Error\n");
        close(this->socket);
        exit(1);
    }

}*/

server::~server() {
    cm->close_socket();
}

//Andrea

void server::handle_req() {

    char *pkt = cm->receive_packet();

    //Andrea test
    //Deserializzazione
    int pos = 0;
    uint8_t opcode;


    memcpy(&opcode, pkt, sizeof(opcode));//prelevo opcode
    opcode = ntohs(opcode);
    pos += sizeof(opcode);

    printf("OPCODE ricevuto: %d\n", opcode);

    if(opcode == LIST){//IMPLEMENT
        //send_list();
        //handle_req(sock);//devo chiamarla? non sono sicuro
    }
    else if(opcode == DOWNLOAD){//IMPLEMENT
    
    }
    else if(opcode == UPLOAD){//IMPLEMENT
    
    }
    else if(opcode == RENAME){//IMPLEMENT
    
    }
    else if(opcode == DELETE){//IMPLEMENT
    
    }
    else if(opcode == LOGOUT){//IMPLEMENT
        printf("Received logout request. Closing connections.\n Bye!\n");
        cm->close_socket();
        exit(0);
    }
    else if(opcode == ACK){

    } else if (opcode == UPLOAD) {//IMPLEMENT

    } else if (opcode == RENAME) {//IMPLEMENT

    } else if (opcode == DELETE) {//IMPLEMENT

    } else if (opcode == LOGOUT) {//IMPLEMENT

    } else if (opcode == ACK) {

    } else if (opcode == CHELLO_OPCODE) {
        client_hello_handler(pkt, pos);
    } else {
        printf("Not a valid opcode\n");
        return;
    }

    return;
}

void server::client_hello_handler(char *pkt, int pos) {

    uint16_t us_size;
    uint16_t nonce_size;

    //Deserializzazione

    memcpy(&us_size, pkt + pos, sizeof(us_size)); //prelevo us_size inizializzo la variabile che dovrà contenerlo
    pos += sizeof(us_size);
    us_size = ntohs(us_size);
    char username[us_size];

    memcpy(&nonce_size, pkt + pos,
           sizeof(nonce_size)); //prelevo nonce_size e inizializzo la variabile che dovrà contenerlo
    pos += sizeof(nonce_size);
    nonce_size = ntohs(nonce_size);
    unsigned char nonce[nonce_size];

    memcpy(&username, pkt + pos, us_size);//prelevo l'username
    pos += us_size;

    memcpy(&nonce, pkt + pos, nonce_size);//prelevo il nonce

    //Fine Deserializzazione

    printf("pacchetto: \n us_size: %d\n nonce_size: %d\n, username: %s\n nonce: %s\n", us_size, nonce_size, username,
           nonce);

    //test andrea
    printf("username ricevuto %s\n", username);
    char test[us_size];
    strcpy(test, username);

    if (strcmp(username, test) == 0) {//username usato per testing metodi
        printf("Username - OK\n");
        uint32_t size;
        char *packet = prepare_ack_packet(&size);
        printf("Test dimensione ack packet: %d\n", size);
        cm->send_packet(packet, size);
        //close(sock);
        //exit(0);
        handle_req();//waits for a request from the client
        //chiama metodo con while true che si blocca in receive packet fino a che non ha ricevuto opcode logout
    } else {
        printf("Username - Error\n");
        close(this->socket);
        exit(1);
    }
}

char *server::prepare_ack_packet(uint32_t *size) {

    char *packet;
    uint8_t opcode = ACK;
    *size = sizeof(opcode);
    memcpy(packet, &opcode, sizeof(opcode));

    return packet;

}

char *server::crt_pkt_download(char *file, int* size) {

    char* pkt = crt_file_pkt(file, size, DOWNLOAD, this->counter);
    this->counter++;
    return pkt;
}

void send_list() {

}

//~Andrea
