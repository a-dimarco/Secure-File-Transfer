#pragma once
#include <iostream>
#include <stdio.h>
#include "../Utils/Socket/connection_manager.h"
#include "client.h"

using namespace std;

char *create_valid_username(char *user)
{ // transforms the username from "user/n" to "user"

    size_t len = strlen(user) - 1;
    char *username = (char *)malloc(len);
    memcpy(username, user, len);

    bool ret = regex_match(username, regex("^[A-Za-z0-9]+$"));
    if (ret)
    {
        return username;
    }
    else
    {
        printf("Username format not correct\n");
    }
}

int main()
{

    cout << "Please, type your username: ";
    char username[11];
    fgets(username, 11, stdin);

    char *clean_username = create_valid_username(username);

    client *cl = new client(clean_username);
    free(clean_username);

    char *pkt = cl->send_clienthello();
    cl->handle_req(pkt);

    // cl->auth(pkt);
    // cl->show_menu();
}
