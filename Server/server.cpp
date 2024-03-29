#include "server.h"

using namespace std;

server::server(int sock) {
    this->socket = sock;
    cm = connection_manager(this->socket);
    this->counter = 0;
}

void server::check_file(unsigned char *pkt, uint8_t opcode) {

    //Decrypts the packet containing a DOWNLOAD/UPLOAD/DELETE request
    //Packet format: OPCODE - COUNTER - SIZE - IV - FILE_NAME - TAG
    int pos = sizeof(uint8_t);
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));

    //Prevents the counter overflow
    if (this->counter == UINT16_MAX)
        throw ExitException("Counter exceeded\n");

    this->counter++;
    count = ntohs(count);

    pos += sizeof(uint16_t);

    //Checks whether the received counter is the expected one
    if (count != this->counter) {
        throw Exception("Counter Error\n");
    }
    uint16_t name_size;
    memcpy(&name_size, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    name_size = ntohs(name_size);

    unsigned char iv[IVSIZE];
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    int cipherlen = name_size;

    unsigned char *ct = (unsigned char *) malloc(cipherlen);
    if (ct == NULL)
        throw Exception("Malloc returned NULL\n");

    memcpy(ct, pkt + pos, name_size);
    pos += name_size;
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) * 2;

    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);
    crypto *c = new crypto();
    unsigned char *pt = (unsigned char *) malloc(name_size);
    if (pt == NULL)
        throw Exception("Malloc returned NULL\n");

    c->decrypt_message(ct, cipherlen, pkt, aad_size, tag, this->shared_key, iv, pt);

    //Checks the format of the received file name
    bool b = nameChecker((char *) pt, FILENAME);
    if (!b) {
        uint32_t size;
        char msg[] = "Inserisci un nome corretto";
        if (this->counter == UINT16_MAX)
            throw ExitException("Counter exceeded\n");

        this->counter++;
        unsigned char *pkto = prepare_msg_packet(&size, msg, sizeof(msg), ACK, this->counter, this->shared_key);
        cm.send_packet(pkto, size);
        return;
    }

    //If a == true, the requested file exists in the correct folder
    bool a;
    a = file_opener((char *) pt, this->logged_user);
    if (a or (opcode == UPLOAD)) {

        //Creates the relative path of the file
        char path[] = "server_file/client/";
        string file_path = path; // ../server_file/client/
        file_path += this->logged_user;   // ../server_file/client/Alice
        file_path += "/file/"; // ../server_file/client/Alice/file/
        file_path += (char *) pt; // ../server_file/client/Alice/file/filename.extension
        size_t len = file_path.length() + 1;
        this->file_name = (char *) malloc(len);
        if (this->file_name == NULL)
            throw Exception("Malloc returned NULL\n");
        memcpy(this->file_name, &file_path[0], len);
    }
    if (opcode == UPLOAD) {
        if (a) {
            //UPLOAD is not allowed here since the file already exists
            uint32_t size;
            char msg[] = "File già esistente";
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            this->counter++;
            //An ACK packet is sent to notify the client
            unsigned char *pkto = prepare_msg_packet(&size, msg, sizeof(msg), ACK, counter, this->shared_key);
            cm.send_packet(pkto, size);
            return;
        }
        //UPLOAD is allowed here
        uint32_t size;
        char msg[] = "File not existing in the sever: OK\n";
        if (this->counter == UINT16_MAX)
            throw ExitException("Counter exceeded\n");
        this->counter++;
        //An UPLOAD packet is sent to notify the client that he's allowed to upload the file
        unsigned char *p = prepare_msg_packet(&size, msg, sizeof(msg), UPLOAD, counter, this->shared_key);
        cm.send_packet(p, size);
    } else if (opcode == DELETE) {
        if (!a) {
            //DELETE is not allowed here since the file does not exist
            char msg[] = "DELETE - FILE NOT FOUND\n";
            unsigned char *pac;
            uint32_t siz;
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            this->counter++;
            //An ACK packet is sent to notify the client
            pac = prepare_msg_packet(&siz, msg, sizeof(msg), ACK, counter, this->shared_key);
            cm.send_packet(pac, siz);
        } else {
            //The file can be deleted
            this->file_name = (char *) malloc(name_size);
            if (this->file_name == NULL)
                throw Exception("Malloc returned NULL\n");
            memcpy(file_name, pt, name_size - 1);
            memcpy(file_name + name_size - 1, "\0", 1);
            char msg[] = "Are you sure?\n";
            unsigned char *pac;
            uint32_t siz;
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            this->counter++;
            //An ACK packet is sent to notify the client
            pac = prepare_msg_packet(&siz, msg, sizeof(msg), DELETE, counter, this->shared_key);
            cm.send_packet(pac, siz);
            //delete_file();
        }
    } else if (opcode == DOWNLOAD) {
        if (a) {
            //The file can be downloaded
            this->counter = send_file(this->file_name, opcode, this->counter, this->shared_key, &this->cm);
            free(this->file_name);
            return;
        } else {
            uint32_t size;
            char msg[] = "File non esistente";
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            this->counter++;
            //The file to download does not exist: an ACK packet is sent to notify the client
            unsigned char *pkto = prepare_msg_packet(&size, msg, sizeof(msg), ACK, this->counter, this->shared_key);
            cm.send_packet(pkto, size);
            return;
        }
    }
    free(pt);
    free(ct);
}

//Closes the server instance
server::~server() {
    cm.close_socket();
    if (this->logged_user){
        free(this->logged_user);
    }
    if (this->shared_key != nullptr) {
        unoptimized_memset(this->shared_key, 0, this->key_size);
        free(this->shared_key);
    }
}

//Receives a packet and decides how to process it according to the opcode
void server::handle_req() {
    try {
        unsigned char *pkt = cm.receive_packet();
        int pos = 0;
        uint8_t opcode;
        memcpy(&opcode, pkt, sizeof(uint8_t));
        pos += sizeof(uint8_t);
        // Opcode Handle

        if (opcode == LIST) {
            //Processes the list request from the client
            handle_list(pkt);
            uint32_t size;
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            this->counter++;
            //Retrieves and send the list
            char s[] = "server_file/client/";
            string temp = print_folder(s);
            int msg_size = temp.length() + 1;
            char msg[msg_size];
            strcpy(msg, temp.c_str());
            unsigned char *pkto = prepare_msg_packet(&size, msg, msg_size, LIST, this->counter, this->shared_key);
            this->cm.send_packet(pkto, size);
        } else if (opcode == DOWNLOAD) {
            check_file(pkt, opcode);
        } else if (opcode == UPLOAD) {
            check_file(pkt, opcode);
            //UPLOAD2 ==> packet containing a little file
        } else if (opcode == UPLOAD2) {
            //Stores the file
            store_file(pkt);
            uint32_t siz;
            char msg[] = "Upload completato!\n";
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            //Notify the client that the UPLOAD is completed successfully
            this->counter++;
            unsigned char *pac = prepare_msg_packet(&siz, msg, sizeof(msg), ACK, this->counter, this->shared_key);
            cm.send_packet(pac, siz);
            free(this->file_name);
            //CHUNK ==> packet containing a chunk of a big file
        } else if (opcode == CHUNK) {
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            this->counter++;
            //Receives the remaining chunks
            this->counter = rcv_file(pkt, this->file_name, this->counter, this->shared_key, &this->cm);
            uint32_t siz;
            char msg[] = "Upload completato!\n";
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            //Notify the client that the UPLOAD is completed succesfully
            this->counter++;
            unsigned char *pac = prepare_msg_packet(&siz, msg, sizeof(msg), ACK, this->counter, this->shared_key);
            cm.send_packet(pac, siz);
            free(this->file_name);
        } else if (opcode == RENAME) {
            if (rename_file(pkt, pos)) {
                //Rename success
                unsigned char *packet;
                uint32_t size;
                char msg[] = "Rename - OK\n";
                if (this->counter == UINT16_MAX)
                    throw ExitException("Counter exceeded\n");
                this->counter++;
                packet = prepare_msg_packet(&size, msg, sizeof(msg), ACK, counter, this->shared_key);
                cm.send_packet(packet, size);
            } else {
                //Rename failure
                unsigned char *packet;
                uint32_t size;
                char msg[] = "Rename - FAIL\n";
                if (this->counter == UINT16_MAX)
                    throw ExitException("Counter exceeded\n");
                this->counter++;
                packet = prepare_msg_packet(&size, msg, sizeof(msg), ACK, counter, this->shared_key);
                cm.send_packet(packet, size);
            }
        } else if (opcode == DELETE) {
            check_file(pkt, opcode);
        } else if (opcode == DELETE_Y) {
            check_msg(pkt);
            delete_file();
        } else if (opcode == DELETE_N) {
            check_msg(pkt);
            free(this->file_name);
            unsigned char *packet;
            uint32_t size;
            char msg[] = "Operation aborted!\n";
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            this->counter++;
            packet = prepare_msg_packet(&size, msg, sizeof(msg), ACK, counter, this->shared_key);
            cm.send_packet(packet, size);

        } else if (opcode == LOGOUT) { // IMPLEMENT
            //Decrypts and verifies the packet
            check_msg(pkt);
            printf("\n[-] Client disconnected :(\n");
            //Close the connection with the client, freeing also the shared session key
            cm.close_socket();
            if (this->shared_key != nullptr) {
                unoptimized_memset(this->shared_key, 0, this->key_size);
                free(this->shared_key);
            }
            this->~server();
            exit(0);
        } else if (opcode == ACK) {
        } else if (opcode == CHELLO_OPCODE) {
            client_hello_handler(pkt, pos);
        } else if (opcode == AUTH) {
            auth(pkt, pos);
        } else {
            throw Exception("Not a valid opcode");
        }

        return;
    } catch (Exception &e) {
        //Unexpected behaviour for which the server shutdown is not needed
        unsigned char *packet;
        uint32_t size;
        //Client is notified with an ACK packet
        packet = prepare_msg_packet(&size, (char *) e.what(), sizeof(e.what()), ACK, counter, this->shared_key);
        cm.send_packet(packet, size);
    } catch (ExitException &e) {
        //Unexpected behaviour for which the server shutdown is needed
        unsigned char *packet;
        uint32_t size;
        //Client is notified with an ack packet
        packet = prepare_msg_packet(&size, (char *) e.what(), sizeof(e.what()), ACK, counter, this->shared_key);
        cm.send_packet(packet, size);
        //Connection with client is closed
        cm.close_socket();
        if (this->shared_key != nullptr) {
            unoptimized_memset(this->shared_key, 0, this->key_size);
            free(this->shared_key);
        }
        exit(1);
    }
}

void server::client_hello_handler(unsigned char *pkt, int pos) {
    uint16_t us_size;
    uint16_t nonce_size;

    // Deserializes the client hello packet

    memcpy(&us_size, pkt + pos, sizeof(us_size)); // Retrieves the username size
    pos += sizeof(us_size);
    us_size = ntohs(us_size);
    this->logged_user = (char *) malloc(us_size);
    if (this->logged_user == NULL) {
        cerr << "Malloc returned NULL\n";
        exit(1);
    }
    memcpy(&nonce_size, pkt + pos,
           sizeof(nonce_size)); // Retrieves the nonce size
    pos += sizeof(nonce_size);
    nonce_size = ntohs(nonce_size);

    unsigned char nonce[NONCESIZE];
    memcpy(this->logged_user, pkt + pos, us_size); // Retrieves the username
    pos += us_size;
    memcpy(nonce, pkt + pos, nonce_size); // Retrieves the nonce

    //Builds and sends the server_hello packet to continue the handshake phase
    server_hello(nonce);
}

//Stores a file that has been uploaded by the client
void server::store_file(unsigned char *pkt) {
    uint32_t ret;
    crypto c = crypto();

    //Deserializes the packet
    int aad_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint16_t count;
    uint32_t file_size;
    int pos = sizeof(uint8_t);
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter == UINT16_MAX)
        throw ExitException("Counter exceeded\n");
    this->counter++;
    if (counter != count) {
        throw Exception("Counter errato\n");
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

    //Devrypts and verifies the packet
    c.decrypt_message(ctext, file_size,
                      pkt, aad_len,
                      tag,
                      this->shared_key,
                      iv,
                      ptext);
    ptext[file_size] = '\0';
    FILE *file = fopen(this->file_name, "wb");
    if (file == nullptr) {
        throw Exception("Error in fopen\n");
    }
    size_t tmp = fwrite(ptext, sizeof(unsigned char), file_size, file);
    if (tmp < UINT32_MAX) {
        ret = (uint32_t) tmp;
    } else {
        throw Exception("Something went wrong\n");
    }
    if (ret < file_size) {
        throw Exception("Error in fwrite\n");
    }
    fclose(file);

    //Erases the file from main memory
    unoptimized_memset(ptext, 0, file_size);

}

//Deserializes, decrypts and verifies a LIST packet
void server::handle_list(unsigned char *pkt) {

    int pos = sizeof(uint8_t);
    if (this->counter == UINT16_MAX)
        throw ExitException("Counter exceeded\n");
    this->counter++;
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter != count) {
        throw Exception("Counter Sbagliato");
    }
    uint16_t size_m;
    memcpy(&size_m, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    size_m = ntohs(size_m);
    crypto *c;
    c = new crypto();
    unsigned char iv[IVSIZE];
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;
    unsigned char *ct = (unsigned char *) malloc(size_m);
    if (ct == NULL)
        throw Exception("Malloc returned NULL\n");
    memcpy(ct, pkt + pos, size_m);
    pos += size_m;
    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char *pt = (unsigned char *) malloc(size_m);
    if (pt == NULL)
        throw Exception("Malloc returned NULL\n");
    unsigned char *aad = (unsigned char *) malloc(aad_size);
    if (aad == NULL)
        throw Exception("Malloc returned NULL\n");
    memcpy(aad, pkt, aad_size);
    c->decrypt_message(ct, size_m, aad, aad_size, tag, this->shared_key, iv, pt);
    free(aad);
    free(ct);
    free(pt);
}

//Prepares a packet containing the list of the files available for the client
unsigned char *server::prepare_list_packet(int *size) {
    uint8_t opcode = LIST;
    char s[] = "server_file/client/";

    //Retrieves the list
    string temp = print_folder(s);
    int msg_size = temp.length() + 1;
    char *msg = (char *) malloc(msg_size);
    if (msg == NULL)
        throw Exception("Malloc returned NULL\n");
    strcpy(msg, temp.c_str());
    int pos = 0;

    //Serializes the packet
    uint32_t ct_size = msg_size;
    int pkt_len = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t) + IVSIZE + ct_size + 16;
    unsigned char *packet = (unsigned char *) malloc(pkt_len);
    if (packet == NULL)
        throw Exception("Malloc returned NULL\n");
    *size = pkt_len;
    memcpy(packet, &opcode, sizeof(opcode)); //OPCode
    pos += sizeof(opcode);

    if (this->counter == UINT16_MAX)
        throw ExitException("Counter exceeded\n");
    this->counter++; //Counter
    int counter2 = counter;
    uint16_t count = htons(counter2);
    memcpy(packet + pos, &count, sizeof(uint16_t));
    pos += sizeof(uint16_t);


    uint16_t size_m = htons(ct_size); //CipherText Size
    memcpy(packet + pos, &size_m, sizeof(uint16_t));
    pos += sizeof(uint16_t);


    crypto *c = new crypto(); //IV
    unsigned char iv[IVSIZE];
    c->create_random_iv(iv);
    memcpy(packet + pos, iv, IVSIZE);
    pos += IVSIZE;

    //Performs the authenticated encryption
    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t); //CipherText & Tag
    unsigned char ct[ct_size];
    unsigned char tag[TAGSIZE];
    c->encrypt_packet((unsigned char *) msg, msg_size, (unsigned char *) packet, aad_size, this->shared_key, iv, ct,
                      tag);
    memcpy(packet + pos, ct, ct_size);
    pos += ct_size;
    memcpy(packet + pos, tag, TAGSIZE);

    return packet;

}

// Takes all files and saves them into a variable

string server::print_folder(char *path) {

    DIR *dir;
    struct dirent *ent;
    string file_list;
    string file_path = path;
    file_path += logged_user;
    file_path += "/file";
    path = &file_path[0];

    int counter2 = 0;

    dir = opendir(path);
    if (!dir) {
        throw Exception("Directory not exists\n");
    }

    // print all the files and directories within directory
    while ((ent = readdir(dir)) != NULL) {
        char *sel_file = ent->d_name;

        if (nameChecker(sel_file, FILENAME)) {
            string temp = string(sel_file);
            file_list += temp;
            file_list += "\n";
            counter2++;
        }
    }
    if (counter2 == 0) {
        file_list += "There are no files in this folder";
    }

    closedir(dir);

    return file_list;
}

//Select a file and remove it, if it exists
//return error otherwise

void server::delete_file() {

    string file_path = "server_file/client/"; //  ../server_file/client/
    file_path += this->logged_user; //  ../server_file/client/Alice
    file_path += "/file/"; //           ../server_file/client/Alice/file/
    file_path += file_name; //          ../server_file/client/Alice/file/filename.extension
    char *filePath = &file_path[0];

    int ret = remove(filePath);
    uint32_t siz;
    free(this->file_name);
    if (ret != 0) {
        char msg[] = "DELETE - ERROR\n";
        unsigned char *pac;
        if (this->counter == UINT16_MAX)
            throw ExitException("Counter exceeded\n");
        this->counter++;
        pac = prepare_msg_packet(&siz, msg, sizeof(msg), ACK, counter, this->shared_key);
        cm.send_packet(pac, siz);
    } else {
        char msg[] = "DELETE - OK\n";
        unsigned char *pac;
        if (this->counter == UINT16_MAX)
            throw ExitException("Counter exceeded\n");
        this->counter++;
        pac = prepare_msg_packet(&siz, msg, sizeof(msg), ACK, counter, this->shared_key);
        cm.send_packet(pac, siz);
    }
}

int server::get_socket() {
    return this->socket;
}

//Builds and sends the server_hello packet
void server::server_hello(unsigned char *nonce) {

    uint8_t opcode = SHELLO_OPCODE;
    crypto *c = new crypto();

    //Generates the server nonce
    this->snonce = (unsigned char *) malloc(NONCESIZE);//TEST
    if (this->snonce == NULL) {
        cerr << "Malloc returned NULL\n";
        exit(1);
    }
    c->create_nonce(snonce);

    string cacert_file_name = "./server_file/server/Server_cert.pem";

    // open the server's certificate:
    FILE *cacert_file = fopen(cacert_file_name.c_str(), "r");
    if (!cacert_file) { throw Exception("Cannot open cert file\n");; }

    // get the file size:
    // (assuming no failures in fseek() and ftell())
    fseek(cacert_file, 0, SEEK_END);
    ulong clear_size = ftell(cacert_file);
    fseek(cacert_file, 0, SEEK_SET);

    // read the certificate from file:
    unsigned char *cert = (unsigned char *) malloc(clear_size);
    if (!cert) {
        cerr << "Malloc returned NULL\n";
        exit(1);
    }
    int ret;
    size_t tmp = fread(cert, 1, clear_size, cacert_file);
    if (tmp < clear_size) { throw Exception("Error while reading file\n"); }
    fclose(cacert_file);
    uint32_t cert_size;
    if (clear_size < UINT32_MAX) {
        cert_size = (uint32_t) clear_size;
    } else {
        throw Exception("Something went wrong\n");
    }

    //Generates the ephemeral ECDH server's private key
    this->my_prvkey = c->dh_keygen();

    uint32_t key_siz;

    //Extracts and serializes the ephemeral ECDH server's public key
    BIO *bio = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_PUBKEY(bio, my_prvkey);
    if (ret == 0) {
        throw Exception("Error in PEM_write_bio_PUBKEY\n");
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    char *key = (char *) malloc(bptr->length);
    if (key == NULL) {
        cerr << "Malloc returned NULL\n";
        exit(1);
    }
    memcpy(key, bptr->data, bptr->length);
    BIO_free(bio);
    key_siz = bptr->length;

    //Prepares the quantities to sign in a single buffer (SERVER_ECDHE_PUBKEY + C_NONCE)
    int sign_size = key_siz + sizeof(nonce);
    unsigned char *tosign = (unsigned char *) malloc(sign_size);
    if (tosign == NULL) {
        cerr << "Malloc returned NULL\n";
        exit(1);
    }
    int pos = 0;
    memcpy(tosign, key, key_siz);
    pos += key_siz;

    uint16_t nonce_size = sizeof(nonce);
    memcpy(tosign + pos, nonce, nonce_size);

    //Digitally signs
    unsigned int sgnt_size;
    unsigned char *sign = c->signn(tosign, sign_size, "./server_file/server/Server_key.pem", &sgnt_size);
    uint32_t pkt_len =
            sizeof(opcode) + sizeof(uint16_t) + sizeof(uint32_t) * 3 + nonce_size + key_siz + cert_size + (sgnt_size);
    unsigned char *pkt = (unsigned char *) malloc(pkt_len);
    if (pkt == NULL) {
        cerr << "Malloc returned NULL\n";
        exit(1);
    }

    //Serializes the server_hello packet
    pos = 0;
    memcpy(pkt, &opcode, sizeof(opcode));
    pos += sizeof(opcode);

    uint16_t nonce_size_s = htons(nonce_size);
    memcpy(pkt + pos, &nonce_size_s, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    uint32_t cert_size_s = htonl(cert_size);
    memcpy(pkt + pos, &cert_size_s, sizeof(uint32_t));
    pos += sizeof(uint32_t);

    uint32_t key_size_s = htonl(key_siz);
    memcpy(pkt + pos, &key_size_s, sizeof(uint32_t));
    pos += sizeof(uint32_t);

    uint32_t sgnt_size_s = htonl(sgnt_size);
    memcpy(pkt + pos, &sgnt_size_s, sizeof(uint32_t));
    pos += sizeof(uint32_t);

    memcpy(pkt + pos, snonce, nonce_size);
    pos += nonce_size;

    memcpy(pkt + pos, cert, cert_size);
    pos += cert_size;

    memcpy(pkt + pos, key, key_siz);
    pos += key_siz;

    memcpy(pkt + pos, sign, ntohl(sgnt_size_s));

    //Sends the server_hello packet
    cm.send_packet(pkt, pkt_len);
    free(tosign);
    free(sign);
    free(key);

}

//Completes the handshake by authenticating the client and deriving the session key
void server::auth(unsigned char *pkt, int pos) {

    int ret;
    crypto *c = new crypto();

    //Deserializes the AUTH packet coming from the client
    uint32_t key_siz;
    memcpy(&key_siz, pkt + pos, sizeof(uint32_t));
    key_siz = ntohl(key_siz);
    pos += sizeof(uint32_t);

    uint32_t sgnt_size;
    memcpy(&sgnt_size, pkt + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);

    sgnt_size = ntohl(sgnt_size);
    unsigned char *key = (unsigned char *) malloc(key_siz);
    if (key == NULL) {
        cerr << "Malloc returned NULL\n";
        exit(1);
    }
    memcpy(key, pkt + pos, key_siz);
    pos += key_siz;

    unsigned char *sign = (unsigned char *) malloc(sgnt_size);
    if (sign == NULL) {
        cerr << "Malloc returned NULL\n";
        exit(1);
    }
    memcpy(sign, pkt + pos, sgnt_size);

    //Deserializes the client's ECDHE public key
    BIO *bio = BIO_new(BIO_s_mem());
    ret = BIO_write(bio, key, key_siz);
    if (ret == 0) {
        throw Exception("Error in Bio_write\n");;
    }

    EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pubkey == NULL) {
        throw Exception("Error in PEM_read_bio_PUBKEY\n");
    }

    unsigned char *to_verify = (unsigned char *) malloc(key_siz + 8);
    if (to_verify == NULL) {
        cerr << "Malloc returned NULL\n";
        exit(1);
    }
    pos = 0;
    memcpy(to_verify + pos, key, key_siz);

    pos += key_siz;
    memcpy(to_verify + pos, this->snonce, NONCESIZE);

    //Creates the path in which the client's RSA long-term public key is stores
    string newnamepath = "server_file/client/"; //    ../server_file/client/
    newnamepath += logged_user; //          ../server_file/client/username
    newnamepath += "/"; //                  ../server_file/client/username/
    newnamepath += "pubkey";
    newnamepath += "/";
    newnamepath += "pubkey.pem";

    //Extracts the client's RSA long-term public key
    char *path = &newnamepath[0];
    FILE *file;
    file = fopen(path, "rb");
    EVP_PKEY *user_pk = PEM_read_PUBKEY(file, NULL, NULL, NULL);

    //Verifies the digital signature made by the client
    bool b = c->verify_sign(sign, sgnt_size, to_verify, key_siz + 8, user_pk);
    if (!b) {
        throw Exception("Signature not valid\n");
    }
    EVP_PKEY_free(user_pk);

    //Derives the shared session key
    unsigned char *g = c->dh_sharedkey(this->my_prvkey, pubkey, &this->key_size);
    this->shared_key = c->key_derivation(g, this->key_size);
    uint32_t pkt_len;
    char msg[] = "Connection established";
    if (this->counter == UINT16_MAX)
        throw ExitException("Counter exceeded\n");
    this->counter++;
    unsigned char *packet = prepare_msg_packet(&pkt_len, msg, sizeof(msg), ACK, counter, this->shared_key);
    cm.send_packet(packet, pkt_len);
    fclose(file);
    BIO_free(bio);
    EVP_PKEY_free(pubkey);
    free(key);
    free(sign);
    free(to_verify);
}

//Deserializes a rename packet and rename
//the file, if it exists

bool server::rename_file(unsigned char *pkt, int pos) {

    //PACKET FORMAT  OPCODE - COUNTER - OLD_NAME_SIZE - NEW_NAME_SIZE - CTSIZE - IV - OLDNAME & NEWNAME - TAG

    uint16_t new_size;
    uint16_t old_size;
    uint32_t cipher_size;

    // Deserialization

    if (this->counter == UINT16_MAX)
        throw ExitException("Counter exceeded\n");
    this->counter++; // Counter
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter != count) {
        throw Exception("Wrong Counter");
    }

    memcpy(&old_size, pkt + pos, sizeof(old_size)); // Old_size
    pos += sizeof(old_size);
    old_size = ntohs(old_size);
    int old_sizer = old_size + 1;
    char *filename = (char *) malloc(old_sizer);
    if (!filename)
        throw Exception("Malloc returned null\n");

    memcpy(&new_size, pkt + pos, sizeof(new_size)); // New_size
    pos += sizeof(new_size);
    new_size = ntohs(new_size);
    int new_sizer = new_size + 1;
    char *newfilename = (char *) malloc(new_sizer);
    if (!newfilename)
        throw Exception("Malloc returned null\n");

    memcpy(&cipher_size, pkt + pos, sizeof(cipher_size)); // Cipher_size
    pos += sizeof(cipher_size);
    cipher_size = ntohl(cipher_size);
    unsigned char *ct = (unsigned char *) malloc(cipher_size);
    if (!ct)
        throw Exception("Malloc returned null\n");

    crypto c = crypto(); // IV
    unsigned char iv[IVSIZE];
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    memcpy(ct, pkt + pos, cipher_size); //CT & TAG
    pos += cipher_size;
    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char *pt = (unsigned char *) malloc(cipher_size);
    if (!pt)
        throw Exception("Malloc returned null\n");
    unsigned char *aad = (unsigned char *) malloc(aad_size);
    if (!aad)
        throw Exception("Malloc returned null\n");
    memcpy(aad, pkt, aad_size);
    c.decrypt_message(ct, cipher_size, aad, aad_size, tag, this->shared_key, iv, pt);

    string temp = (char *) pt;
    string old = temp.substr(0, old_size);
    string news = temp.substr(old_size, new_size);

    strcpy(filename, old.c_str()); // Old name
    strcpy(newfilename, news.c_str()); // New name

    // End Deserialization

    if (nameChecker(filename, FILENAME)) //Check if username format is correct
    {
        if (file_opener(filename, logged_user) && !file_opener(newfilename,logged_user)) //Check if the file exists
        {
            bool b = file_renamer(newfilename, filename);
            if (b) {
                free(ct);
                free(newfilename);
                free(filename);
                free(aad);
                free(pt);
                return true;
            } else {
                free(ct);
                free(newfilename);
                free(filename);
                free(aad);
                free(pt);
                return false;
            }

        } else {
            free(ct);
            free(newfilename);
            free(filename);
            free(aad);
            free(pt);
            return false;
        }
    } else {
        free(ct);
        free(newfilename);
        free(filename);
        free(aad);
        free(pt);

        return false;
    }

    /*free(ct);
    free(newfilename);
    free(filename);
    free(aad);
    free(pt);*/
}

bool server::file_renamer(char *new_name, char *old_name) {

    string newnamepath = "server_file/client/"; //    ../server_file/client/
    newnamepath += logged_user; //          ../server_file/client/username
    newnamepath += "/file/"; //             ../server_file/client/username/file/
    newnamepath += new_name; //             ../server_file/client/username/file/newname.extension

    string oldnamepath = "server_file/client/"; //    ../server_file/client/
    oldnamepath += logged_user; //          ../server_file/client/username
    oldnamepath += "/file/"; //             ../server_file/client/username/file/
    oldnamepath += old_name; //             ../server_file/client/username/file/oldname.extension

    old_name = &oldnamepath[0];
    new_name = &newnamepath[0];

    if (rename(old_name, new_name) != 0) {
        return false;
    } else {
        return true;
    }

}

void server::check_msg(unsigned char *pkt) {
    // PACKET FORMAT: OPCODE - COUNTER - CPSIZE - IV - CIPHERTEXT - TAG

    int pos = sizeof(uint8_t);

    if (this->counter == UINT16_MAX - 2) //Check counter overflow
    {
        throw ExitException("Counter Exceeded\n");
    }
    this->counter++;
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t)); //Counter
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter != count) {
        throw ExitException("Wrong counter!");
    }

    uint16_t size_m; // CPSize
    memcpy(&size_m, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    size_m = ntohs(size_m);

    crypto *c; // IV
    c = new crypto();
    unsigned char iv[IVSIZE];
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    unsigned char ct[size_m]; //Ciphertext & Tag
    memcpy(ct, pkt + pos, size_m);
    pos += size_m;
    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char pt[size_m];
    unsigned char aad[aad_size];
    memcpy(aad, pkt, aad_size);
    c->decrypt_message(ct, size_m, aad, aad_size, tag, this->shared_key, iv, pt);

    printf("%s\n", pt);
}
