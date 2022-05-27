#include <iostream>
#include <string.h>
#include "server.h"
#include <signal.h>
#include <unistd.h>
#include "../Utils/Socket/connection_manager.h"

using namespace std;

void signal_callback_handler() {
    cout << "Server shutting down " << endl;
    // Terminate program
    exit(1);
}

void handle_req(int sock) {//TEST deserializza e gestisce il 1° packet dell'handshake con il server
    connection_manager *cm = new connection_manager(sock);
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
        /*close(sock);
        exit(0);*/
        char *pkt = cm->receive_packet();//waits for a request from the client

    }
    else{
        printf("Username - Error\n");
        close(sock);
        exit(1);
    }

}

//Andrea

void opcode_handler(uint8_t opcode){

    if(opcode == LIST){//IMPLEMENT
        send_list();
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
    
    }
    else{
        printf("Not a valid opcode\n");
        return;
    }

    return;
}

void send_list(){

}

//~Andrea

int main() {
    char addr[] = "127.0.0.1";
    long std_port = 49151;
    connection_manager *cm = new connection_manager(addr, std_port);
    cm->listening(10);
    //signal(SIGINT, signal_callback_handler);
    int sock;
    while (true) {
        sock = cm->accepting();
        pid_t pid = fork();
        if (pid == 0) {
            cm->close_socket();
            handle_req(sock);
            exit(0);
        } else
            cm->close_socket(sock);
    }


}
