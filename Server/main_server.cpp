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

void handle_req(int sock){
    connection_manager *cm=new connection_manager(sock);
    char* pkt=cm->receive_packet();
}

int main() {
    char addr[]="127.0.0.1";
    long std_port=49151;
    connection_manager *cm=new connection_manager(addr,std_port);
    cm->listening(10);
    //signal(SIGINT, signal_callback_handler);
    int sock;
    while(true){
        sock=cm->accepting();
        pid_t pid = fork();
        if (pid == 0)
        {
            cm->close_socket();
            handle_req(sock);
            exit(0);
        }
        else
            cm->close_socket(sock);
    }


}
