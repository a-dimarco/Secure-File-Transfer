#include <iostream>
//#include "client.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <iostream>
#include <string>
#include <limits.h>
#include "../Utils/Socket/connection_manager.h"
#include "client.h"
#include <typeinfo>

using namespace std;

int main() {

    cout<<"Ducange culo\n";
    cout << "Please, type your username: ";
    char username[11];
    fgets(username, 11, stdin);
    client *cl = new client(username);
    char *pkt = cl->send_clienthello();
    cl->auth(pkt);

}
