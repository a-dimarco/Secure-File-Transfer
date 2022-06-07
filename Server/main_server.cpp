#include <iostream>
#include "server.h"
#include <unistd.h>


using namespace std;

int sockfd;

/* Check CTRL-C */
void signal_callback_handler(int flag) {
    printf("\n[+] Process %d shutting down...(Flag %d)\n", getpid(), flag);
    close(sockfd);
    exit(1);
}

/* Server standard port */
#define PORT 4444

int main() {

    int ret;

    /* Server socket structure */
    struct sockaddr_in serverAddr;

    /* Client Socket id */
    int clientSocket;

    /* Client socket structure */
    struct sockaddr_in cliAddr;

    /* byte size of server socket address */
    socklen_t addr_size;

    /* Child process id */
    pid_t childpid;

    /* Creation of the server socket id */
    int sockfd = -1;
    while (sockfd < 0) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }

    /* Set flag in order to be able to reopen the socket */
    const int trueFlag = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));

    printf("[+] Socket created.\n");

    /*Initializing address structure with NULL */
    memset(&serverAddr, '\0',
           sizeof(serverAddr));

    /* Assign port number and IP address
   * to the socket created*/
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);

    serverAddr.sin_addr.s_addr
            = inet_addr("127.0.0.1");

    /* Binding the socket id with
    * the socket structure*/
    ret = bind(sockfd,
               (struct sockaddr *) &serverAddr,
               sizeof(serverAddr));

    if (ret < 0) {
        printf("Error in binding.\n");
        exit(1);
    }

    /* Listening for connections (upto 10) */
    if (listen(sockfd, 10) == 0) {
        printf("[+] Server - ON\n");
    }

    //int cnt=0;

    /* Check CTRL-C */
    signal(SIGINT, signal_callback_handler);

    while (1) {

        /* Accept clients and
        * store their information in cliAddr */
        clientSocket = accept(
                sockfd, (struct sockaddr *) &cliAddr,
                &addr_size);

        if (clientSocket < 0) {
            printf("Error in connection");
            exit(1);
        }
/*
        printf("Connection accepted from %s:%d\n",
               inet_ntoa(cliAddr.sin_addr),
               ntohs(cliAddr.sin_port));*/

        printf("[+] Client connected!\n\n");

        /* Creates a child process */
        if ((childpid = fork()) == 0) {


            /* Closing the server socket id */
            close(sockfd);

            /* New server object (one for each client) */
            server s = server(clientSocket);

            /* Handling client requests */
            while (true) {

                s.handle_req();

            }
        } else {
            close(clientSocket);
        }
    }
}