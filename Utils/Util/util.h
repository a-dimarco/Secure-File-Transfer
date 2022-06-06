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
using namespace std;
class Exception: public std::runtime_error
{
public:
    Exception(std::string const& msg):
            std::runtime_error(msg)
    {}
};
unsigned char *crt_file_pkt(uint32_t clear_size,unsigned char* clear,uint32_t *size, uint8_t opcode, uint16_t counter, unsigned char* shared_key);
bool nameChecker(char *name, int mode);
bool file_opener(char *filename, char *username);
unsigned char *prepare_msg_packet(uint32_t *size, char *msg, int msg_size,uint8_t opcode, int counter2, unsigned char* shared_key);
void write_chunk(unsigned char* pkt, FILE* file, uint16_t counter, unsigned char* shared_key);
int send_file(char *filename, uint8_t opcode, uint16_t counter, unsigned char* shared_key, connection_manager* cm);
int rcv_file(unsigned char* pkt, char *filename, uint16_t counter, unsigned char* shared_key, connection_manager* cm);