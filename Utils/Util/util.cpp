#include "util.h"
//#include "sodium.h"
#include <sys/stat.h>
#include <fstream>
#include <cmath>
//#include "sodium/randombytes.h"
//#include "sodium/core.h"

/* Prepare a classic packet with a message inside */
unsigned char *
prepare_msg_packet(uint32_t *size, char *msg, int msg_size, uint8_t opcode, int counter2, unsigned char *shared_key) {

    int pos = 0;
    uint16_t ct_size = msg_size;
    int pkt_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t) + IVSIZE + ct_size + TAGSIZE;
    unsigned char *packet = (unsigned char *) malloc(pkt_len);
    if (packet == NULL) {
        throw ExitException("Malloc returned null");
    }
    *size = pkt_len;

    memcpy(packet, &opcode, sizeof(opcode)); //OPCode
    pos += sizeof(opcode);

    uint16_t count = htons(counter2);
    memcpy(packet + pos, &count, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    ct_size = htons(ct_size);
    memcpy(packet + pos, &ct_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    ct_size = ntohs(ct_size);

    crypto *c = new crypto();

    unsigned char iv[IVSIZE];
    c->create_random_iv(iv);
    memcpy(packet + pos, iv, IVSIZE);
    pos += IVSIZE;

    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char ct[ct_size];
    unsigned char tag[TAGSIZE];

    c->encrypt_packet((unsigned char *) msg, msg_size, (unsigned char *) packet, aad_size, shared_key, iv, ct, tag);

    memcpy(packet + pos, ct, ct_size);
    pos += ct_size;

    memcpy(packet + pos, tag, TAGSIZE);

    return packet;
}

/* Creates a packet with file bytes inside */
unsigned char *crt_file_pkt(uint32_t clear_size, unsigned char *clear, uint32_t *size, uint8_t opcode, uint16_t counter,
                            unsigned char *shared_key) {
    if (opcode == UPLOAD) {
        opcode = UPLOAD2;
    }

    int pos1 = 0;
    crypto c = crypto();
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint32_t pkt_len = aad_size + IVSIZE + clear_size + TAGSIZE;

    unsigned char *final_packet = (unsigned char *) malloc(pkt_len);
    if (final_packet == NULL) {
        cerr << "Malloc return NULL";
        exit(1);
    }
    memcpy(final_packet, &opcode, sizeof(uint8_t));
    pos1 += sizeof(uint8_t);

    uint16_t n_counter = htons(counter);
    memcpy(final_packet + pos1, &n_counter, sizeof(uint16_t));
    pos1 += sizeof(uint16_t);
    clear_size = htonl(clear_size);

    memcpy(final_packet + pos1, &clear_size, sizeof(uint32_t));
    clear_size = ntohl(clear_size);
    pos1 += sizeof(uint32_t);

    unsigned char iv[IVSIZE];
    c.create_random_iv(iv);

    unsigned char ciphertext[clear_size];
    unsigned char tag[TAGSIZE];
    c.encrypt_packet(clear, clear_size, final_packet, aad_size, shared_key, iv, ciphertext, tag);

    memcpy(final_packet + pos1, iv, IVSIZE);
    pos1 += IVSIZE;

    memcpy(final_packet + pos1, ciphertext, clear_size);
    pos1 += clear_size;

    memcpy(final_packet + pos1, tag, TAGSIZE);
    *size = pkt_len;

    return final_packet;
}

/* Checks if the command or filename is in the correct format */
bool nameChecker(char *name, int mode) {

    bool ret;

    if (mode == FILENAME) {
        ret = regex_match(name, regex("^[A-Za-z0-9]*\\.[A-Za-z0-9]+$"));
    } else if (mode == COMMAND) {
        ret = regex_match(name, regex("^\\![A-Za-z]+$"));
    } else {
        ret = false;
    }

    return ret;
}

/* Checks the existence of a file */
bool file_opener(char *filename, char *username) {

    char *path;
    string file_path = "server_file/client/";
    file_path += username;

    path = &file_path[0];

    FILE *source;

    DIR *dir;
    dir = opendir(path);
    if (!dir) {
        throw Exception("Directory doesn't exist\n");
    }

    closedir(dir);
    file_path += "/file/";
    file_path += filename;

    char *filepath = &file_path[0];

    source = fopen(filepath, "rb");

    if (source == NULL) {

        return false;
    } else {
        fclose(source);

        return true;
    }
}

/* Creates a generic request for a file */
unsigned char *crt_request_pkt(char *filename, int *size, uint8_t opcode, uint16_t counter, unsigned char *shared_key) {

    crypto c = crypto();

    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) * 2;
    uint16_t ptext_size = htons(strlen(filename) + 1);
    int pos = 0;
    int cipherlen;
    uint16_t n_counter = htons(counter);
    *size = aad_size + IVSIZE + ptext_size + 2 * 16;

    unsigned char *pkt = (unsigned char *) malloc(*size);
    if (pkt == NULL) {
        cerr << "Malloc return NULL";
        exit(1);
    }

    unsigned char iv[IVSIZE];
    c.create_random_iv(iv);

    unsigned char tag[TAGSIZE];

    memcpy(pkt, &opcode, sizeof(uint8_t));
    pos += sizeof(uint8_t);

    memcpy(pkt + pos, &n_counter, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    memcpy(pkt + pos, &ptext_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    memcpy(pkt + pos, iv, IVSIZE);
    pos += IVSIZE;

    cipherlen = c.encrypt_packet((unsigned char *) filename, strlen(filename) + 1,
                                 (unsigned char *) pkt, aad_size, shared_key, iv,
                                 (unsigned char *) pkt + pos, tag);

    pos += cipherlen;
    memcpy(pkt + pos, tag, 16);

    return pkt;
}

/* Sends an entire file */
int send_file(char *filename, uint8_t opcode, uint16_t counter, unsigned char *shared_key, connection_manager *cm) {

    uint32_t ret;
    FILE *file;

    file = fopen(filename, "rb");
    if (file == NULL) {
        throw Exception("Error in fopen\n");
    }

    struct stat st;
    if (stat(filename, &st) != 0) {
        return 0;
    }
    uint64_t file_size = st.st_size;

    if (file_size > UINT32_MAX) {
        throw Exception("File too big\n");
    }

    if (counter > UINT16_MAX - ceil(file_size / CHUNK_SIZE))
        throw ExitException("Counter will exceed\n");

    if (file_size < CHUNK_SIZE) {
        unsigned char clear[file_size];
        size_t tmp = fread(clear, sizeof(unsigned char), file_size, file);
        if (tmp < UINT32_MAX) {
            ret = (uint32_t) tmp;
        } else {
            throw Exception("Something went wrong\n");
        }
        if (ret < file_size) {
            throw Exception("Error in reading the file\n");
        }
        uint32_t size;
        uint32_t file_siz = (uint32_t) file_size;
        counter++;
        unsigned char *pkt = crt_file_pkt(file_siz, clear, &size, opcode, counter, shared_key);
        cm->send_packet(pkt, size);
        fclose(file);

    } else {

        opcode = CHUNK;
        uint32_t sent = 0;
        uint32_t current_len;
        uint32_t size;

        while (sent < file_size) {
            current_len = (file_size - sent < CHUNK_SIZE) ? file_size - sent : CHUNK_SIZE;
            if (sent + current_len == file_size) {
                opcode = FINAL_CHUNK;
            }
            void *fragment = malloc(current_len);
            if (fragment == NULL) {
                cerr << "Errore nella malloc";
            }

            size_t tmp = fread(fragment, sizeof(unsigned char), current_len, file);
            if (tmp < UINT32_MAX) {
                ret = (uint32_t) tmp;
            } else {
                throw Exception("Something went wrong");
            }
            if (ret < current_len) {
                throw Exception("Error in fread");
            }
            counter++;
            unsigned char *pkt = crt_file_pkt(current_len, (unsigned char *) fragment, &size, opcode, counter,
                                              shared_key);
            cm->send_packet(pkt, size);
            sent += current_len;
            free(fragment);
        }

        fclose(file);
    }
    return counter;
}

/* Receives an entire file */
int rcv_file(unsigned char *pkt, char *filename, uint16_t counter, unsigned char *shared_key, connection_manager *cm) {

    FILE *file = fopen(filename, "wb");

    if (file == nullptr) {
        throw Exception("Error in fopen\n");
    }

    write_chunk(pkt, file, counter, shared_key);

    uint8_t opcode = CHUNK;
    unsigned char *pkto;

    while (opcode == CHUNK) {

        pkto = cm->receive_packet();
        memcpy(&opcode, pkto, sizeof(opcode));
        counter++;

        write_chunk(pkto, file, counter, shared_key);

    }

    fclose(file);

    return counter;
}

/* Write only a single chunk of the file */
void write_chunk(unsigned char *pkt, FILE *file, uint16_t counter, unsigned char *shared_key) {
    uint32_t ret;
    crypto c = crypto();
    int aad_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint16_t count;
    uint32_t file_size;
    int pos = sizeof(uint8_t);

    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);

    if (counter != count) {
        throw Exception("Wrong counter \n");
    }

    memcpy(&file_size, pkt + pos, sizeof(uint32_t));
    file_size = ntohl(file_size);
    pos += sizeof(uint32_t);

    unsigned char iv[IVSIZE];
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    unsigned char ctext[file_size];
    memcpy(ctext, pkt + pos, file_size);
    pos += file_size;

    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);
    unsigned char ptext[file_size + 1];

    c.decrypt_message(ctext, file_size, pkt, aad_len, tag, shared_key, iv, ptext);

    ptext[file_size] = '\0';

    size_t tmp = fwrite(ptext, sizeof(unsigned char), file_size, file);
    if (tmp < UINT32_MAX) {
        ret = (uint32_t) tmp;
    } else {
        throw Exception("Something went wrong\n");
    }
    if (ret < file_size) {
        throw Exception("Error in fwrite\n");
    }

    unoptimized_memset(ptext, 0, file_size);
}

/* Unoptimized memset => not ignored by the compiler */
#pragma GCC push_options
#pragma GCC optimize("O0")

void *unoptimized_memset(unsigned char *mem, int c, size_t len) {
    return memset(mem, c, len);
}

#pragma GCC pop_options


