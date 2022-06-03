#include <iostream>
#include "server.h"
#include <unistd.h>

using namespace std;

//int socket;
connection_manager cm;

void signal_callback_handler(int flag)
{
    cout << "Server shutting down " << endl;
    cm.close_socket();
    // Terminate program
    exit(1);
}

void start_session(int sock)
{
    server *s = new server(sock);
    while(true) {
        s->handle_req();
    }
}

int main()
{
    char addr[] = "127.0.0.1";
    // long std_port = 49151;
    long std_port = 6666;
    cm = connection_manager(addr, std_port);
    cm.listening(10);
    signal(SIGINT, signal_callback_handler);
    int sock;
    while (true)
    {
        sock = cm.accepting();
        
        pid_t pid = fork();
        if (pid == 0)
        {
            cm.close_socket();
            server *s = new server(sock);
            while(true) {
                s->handle_req();
            }
            exit(0);
        }
        else
            cm.close_socket(sock);
        
    }
}
