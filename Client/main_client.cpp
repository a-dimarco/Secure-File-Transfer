#include <iostream>
#include <stdio.h>
#include "../Utils/Socket/connection_manager.h"
#include "client.h"

using namespace std;

/* Server port number */
#define PORT 4444

int main() {

    int clientSocket, ret; // Socket id

    /* Client socket structure */
    struct sockaddr_in cliAddr;

    /* Creating socket id */
    clientSocket = socket(AF_INET,
                          SOCK_STREAM, 0);

    /* Set a flag in order to be able
     * to reopen the socket */
    const int trueFlag = 1;
    setsockopt(clientSocket, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));

    if (clientSocket < 0) {
        printf("Error in connection.\n");
        exit(1);
    }
    printf("[+] Socket created.\n");

    /* Initializing socket structure with NULL */
    memset(&cliAddr, '\0', sizeof(cliAddr));

    struct sockaddr_in serverAddr;

    /* Assigning port number and IP address */
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);

    serverAddr.sin_addr.s_addr
            = inet_addr("127.0.0.1");

    /* Connection to server */
    ret = connect(clientSocket,
                  (struct sockaddr *) &serverAddr,
                  sizeof(serverAddr));
    if (ret < 0) {
        printf("Error in connection.\n");
        exit(1);
    }

    printf("[+] Connected to the Server!\n");

    /* Username form */
    cout << "Please, type your username: ";
    char username[10];
    char *check = fgets(username, 10, stdin);
    if (check == nullptr) {
        throw Exception("Error in fgets");
    }

    /* Cleaning of stdin buffer */
    if (!strchr(username, '\n')) {
        printf("Error - username exceeding 10 characters\n");
        char c[2];
        while (c[0] != '\n') {
            check = fgets(c, 2, stdin);
            if (check == nullptr) {
                throw Exception("Error in fgets");
            }
        }
        return 0;
    }

    username[strcspn(username, "\n")] = 0;

    /* New client object */
    client cl = client(username, clientSocket);

    /* Sending Client Hello message
     * to the server */
    cl.send_clienthello();

    /* Handling the packet until
     * logout */
    while (true) {

        cl.handle_req();
        
    }

}

