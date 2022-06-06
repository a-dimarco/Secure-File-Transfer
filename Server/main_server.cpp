#include <iostream>
#include "server.h"
#include <unistd.h>


using namespace std;


int sockfd;

void signal_callback_handler(int flag) {
    printf("\n[+] Process %d shutting down...\n",getpid());
    close(sockfd);
// Terminate program
    exit(1);
}



// PORT number
#define PORT 4444


int main() {
// Server socket id
    int ret;



// Server socket address structures
    struct sockaddr_in serverAddr;



// Client socket id
    int clientSocket;



// Client socket address structures
    struct sockaddr_in cliAddr;



// Stores byte size of server socket address
    socklen_t addr_size;



// Child process id
    pid_t childpid;



/*
// Creates a TCP socket id from IPV4 family
sockfd = socket(AF_INET, SOCK_STREAM, 0);
// Error handling if socket id is not valid
if (sockfd < 0) {
printf("Error in creating the socket.\n");
exit(1);
}
*/
    int sockfd = -1;
    while (sockfd < 0) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }


    const int trueFlag = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));


    printf("[+] Socket created.\n");



// Initializing address structure with NULL
    memset(&serverAddr, '\0',
           sizeof(serverAddr));



// Assign port number and IP address
// to the socket created
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);



// 127.0.0.1 is a loopback address
    serverAddr.sin_addr.s_addr
            = inet_addr("127.0.0.1");



// Binding the socket id with
// the socket structure
    ret = bind(sockfd,
               (struct sockaddr *) &serverAddr,
               sizeof(serverAddr));



// Error handling
    if (ret < 0) {
        printf("Error in binding.\n");
        exit(1);
    }



// Listening for connections (upto 10)
    if (listen(sockfd, 10) == 0) {
        printf("[+] Server - ON\n");
    }

    int cnt=0;
    signal(SIGINT, signal_callback_handler);
    while (1) {



// Accept clients and
// store their information in cliAddr
        clientSocket = accept(
                sockfd, (struct sockaddr *) &cliAddr,
                &addr_size);



// Error handling

        if (clientSocket < 0) {
            printf("Error in connection");
            exit(1);
        }



/*
        printf("Connection accepted from %s:%d\n",
               inet_ntoa(cliAddr.sin_addr),
               ntohs(cliAddr.sin_port));*/


        printf("[+] Client connected!\n\n");


// Creates a child process
        if ((childpid = fork()) == 0) {



// Closing the server socket id
            close(sockfd);
            server s = server(clientSocket);
            while (true) {
                s.handle_req();

            }


        }/*else{
            close(clientSocket);
        }
        */
    }



// Close the client socket id
    close(clientSocket);
    return 0;
}