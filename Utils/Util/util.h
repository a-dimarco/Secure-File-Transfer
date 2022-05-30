#include "../Crypto/crypto.h"
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <regex>
#include "../Socket/connection_manager.h"
using namespace std;
#ifndef SECURE_FILE_TRANSFER_UTIL_H
#define SECURE_FILE_TRANSFER_UTIL_H

#endif // SECURE_FILE_TRANSFER_UTIL_H

char *crt_file_pkt(char *filename, int *size, uint8_t opcode, uint16_t counter);
bool nameChecker(char *name, int mode);
bool file_opener(char *filename, char *username);