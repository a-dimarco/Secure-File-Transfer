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

    char *pkt = cl->send_clienthello();
    cl->handle_req(pkt);



    // cl->auth(pkt);
    // cl->show_menu();
}
