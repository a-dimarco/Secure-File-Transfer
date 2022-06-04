#include <iostream>
#include <stdio.h>
#include "../Utils/Socket/connection_manager.h"
#include "client.h"

using namespace std;
int main()
{

    cout << "Please, type your username: ";
    char username[11];
    fgets(username, 11, stdin);

    username[strcspn(username,"\n")] = 0;


    client *cl = new client(username);

    cl->send_clienthello();
    while(true) {
        cl->handle_req();
    }

    // cl->auth(pkt);
    // cl->show_menu();
}
