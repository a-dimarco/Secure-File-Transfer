#include <iostream>
#include <stdio.h>
#include "../Utils/Socket/connection_manager.h"
#include "client.h"

using namespace std;

// PORT number
#define PORT 4444

int main() {
    // Socket id
    int clientSocket, ret;

    // Client socket structure
    struct sockaddr_in cliAddr;

    // char array to store incoming message

    // Creating socket id
    clientSocket = socket(AF_INET,
                          SOCK_STREAM, 0);

    const int trueFlag = 1;
    setsockopt(clientSocket, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));

    if (clientSocket < 0) {
        printf("Error in connection.\n");
        exit(1);
    }
    printf("[+] Socket created.\n");

    // Initializing socket structure with NULL
    memset(&cliAddr, '\0', sizeof(cliAddr));

    /*
    cliAddr.sin_family = AF_INET;
    cliAddr.sin_port = htons(6666);
    inet_pton(AF_INET, "127.0.0.1", &cliAddr.sin_addr);
    ret = bind(clientSocket, (struct sockaddr *)&cliAddr, sizeof(cliAddr));
    if (ret < 0)
    {
        cerr << "Binding Error\n";

        exit(1);
    }
    */
    struct sockaddr_in serverAddr;
    // Assigning port number and IP address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);

    // 127.0.0.1 is Loopback IP
    serverAddr.sin_addr.s_addr
            = inet_addr("127.0.0.1");

    // connect() to connect to the server
    ret = connect(clientSocket,
                  (struct sockaddr *) &serverAddr,
                  sizeof(serverAddr));

    if (ret < 0) {
        printf("Error in connection.\n");
        exit(1);
    }

    printf("[+] Connected to the Server!\n");

    cout << "Please, type your username: ";
    char username[11];
    fgets(username, 11, stdin);

    username[strcspn(username, "\n")] = 0;


    client cl = client(username, clientSocket);

    cl.send_clienthello();
    while (true) {
        cl.handle_req();
    }

}

