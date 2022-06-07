#include "client.h"
#include <stdio.h>
#include <openssl/rand.h>

using namespace std;

client::client() = default;;

/* Creates a client object storing username and socket*/
client::client(char *username, int sock) {

    this->user = new char[USERNAMESIZE];
    memcpy((void *) this->user, (void *) username, USERNAMESIZE);

    this->cm = connection_manager(sock);
    this->counter = 0;

}

/* Sends to the server the Client Hello message */
void client::send_clienthello() {

    crypto c = crypto();

    nonce = (unsigned char *) malloc(NONCESIZE);
    if (nonce == NULL) {
        cerr << "Malloc return NULL";
        exit(1);
    }

    c.create_nonce(nonce);

    unsigned char *pkt = this->crt_pkt_hello();
    this->cm.send_packet(pkt, CLIENT_HELLO_SIZE);

}

/* Creates the packet for the Client Hello */
unsigned char *client::crt_pkt_hello() {

    uint16_t us_size = htons(strlen(user) + 1);
    uint16_t nonce_size = htons(sizeof(nonce));
    uint8_t opcode = CHELLO_OPCODE;

    int pos = 0;

    auto *pkt = (unsigned char *) malloc(CLIENT_HELLO_SIZE);
    if (pkt == NULL) {
        cerr << "Malloc return NULL";
        exit(1);
    }

    memcpy(pkt, &opcode, sizeof(uint8_t)); //OPCODE
    pos += sizeof(uint8_t);

    memcpy(pkt + pos, &us_size, sizeof(uint16_t)); //Size of the username
    pos += sizeof(uint16_t);

    memcpy(pkt + pos, &nonce_size, sizeof(uint16_t)); //Size of the nonce
    pos += sizeof(uint16_t);

    memcpy(pkt + pos, user, strlen(user) + 1); //Username
    pos += strlen(user) + 1;

    memcpy(pkt + pos, nonce, NONCESIZE); //Nonce

    return pkt;
}

/* Sends the final message of the handshake */
void client::auth(unsigned char *nounce, EVP_PKEY *pubkey) {

    crypto c = crypto();

    /* Creation of "a" for g^a */
    EVP_PKEY *my_prvkey = c.dh_keygen();

    uint32_t key_siz;

    /* Serialization of g^a to unsigned char*/
    BIO *bio = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_PUBKEY(bio, my_prvkey);
    if (ret == 0) {
        cerr << "Error: PEM_write_bio_PUBKEY returned " << ret << "\n";
        exit(1);
    }
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);;
    BIO_set_close(bio, BIO_NOCLOSE);
    unsigned char key[bptr->length];
    memcpy(key, bptr->data, bptr->length);
    key_siz = bptr->length;

    /* Definition of what has to be signed (key+nonce) */
    uint sign_size = key_siz + sizeof(nounce);
    unsigned char tosign[sign_size];
    int pos = 0;
    memcpy(tosign, key, key_siz);
    pos += (int) key_siz;
    uint16_t nonce_size = NONCESIZE;
    memcpy(tosign + pos, nounce, nonce_size);
    unsigned int sgnt_size;

    /* Set the private key path */
    string path = "client_file/";
    path = path + this->user + "/";
    path = path + this->user + ".pem";

    /* Signature generation */
    unsigned char *sign = c.signn(tosign, sign_size, path, &sgnt_size);

    /* Packet generation */
    uint8_t opcode = AUTH;
    uint32_t pkt_len = sizeof(opcode) + sizeof(uint32_t) * 2 + key_siz + sgnt_size;
    auto *pkt = (unsigned char *) malloc(pkt_len);
    if (pkt == NULL) {
        cerr << "Malloc return NULL";
        exit(1);
    }

    pos = 0;
    memcpy(pkt + pos, &opcode, sizeof(uint8_t)); //OPCODE
    pos += sizeof(uint8_t);

    uint32_t key_size_s = htonl(key_siz); //Key Size
    memcpy(pkt + pos, &key_size_s, sizeof(uint32_t));
    pos += sizeof(uint32_t);

    uint32_t sgnt_size_s = htonl(sgnt_size); //Signature Size
    memcpy(pkt + pos, &sgnt_size_s, sizeof(uint32_t));
    pos += sizeof(uint32_t);

    memcpy(pkt + pos, key, ntohl(key_size_s)); // Key 
    pos += (int) ntohl(key_size_s);

    memcpy(pkt + pos, sign, ntohl(sgnt_size_s));// Signature
    unsigned char *g = c.dh_sharedkey(my_prvkey, pubkey, &this->key_size);
    this->shared_key = c.key_derivation(g, this->key_size);

    this->cm.send_packet(pkt, pkt_len);

    /* Clean up */
    EVP_PKEY_free(pubkey);
    BIO_free(bio);
    free(sign);
}

/* Client destructor, to be sure that
 * the socket is close and the key
 * cleaned if present */
client::~client() {

    this->cm.close_socket();

    if (this->shared_key != nullptr) {
        unoptimized_memset(this->shared_key, 0, this->key_size);
        free(this->shared_key);
    }
}

/* Commands */
void client::print_commands() {
    printf("\nPlease select a command\n");
    printf("!list --> Show all files uploaded to the server\n");
    printf("!download --> Download a file from the server\n");
    printf("!upload --> Upload a file to the server\n");
    printf("!rename --> Rename a file stored into the server\n");
    printf("!delete --> Delete a file stored into the server\n");
    printf("!logout --> Disconnect from the server and close the application\n\n");
}

/* Handler of the packet */
void client::handle_req() {
    try {
        unsigned char *pkt = this->cm.receive_packet();

        int pos = 0;
        uint8_t opcode;

        memcpy(&opcode, pkt, sizeof(opcode)); // OPCode
        pos += sizeof(opcode);

        /* Check what to do */
        if (opcode == SHELLO_OPCODE) {

            server_hello_handler(pkt, pos);

        } else if (opcode == LIST) {

            printf("Received List\n");
            show_list(pkt, pos);
            show_menu();

        } else if (opcode == ACK) {

            handle_ack(pkt);
            show_menu();

        } else if (opcode == DELETE) {
            handle_ack(pkt);
            cout << "'Yes' to delete \n";
            char command[5];
            char *check = fgets(command, 5, stdin);
            if (check == nullptr) {
                throw Exception("Error in fgets");
            }
            if (!strchr(command, '\n')) {
                printf("Error: command exceeding character limit\n");
                char c[2];
                while (c[0] != '\n') {
                    check = fgets(c, 2, stdin);
                    if (check == nullptr) {
                        throw Exception("Error in fgets");
                    }
                }
            }
            command[strcspn(command, "\n")] = 0;
            uint32_t size;
            if (this->counter == UINT16_MAX - 2) //Check counter overflow
            {
                throw ExitException("Counter Exceeded\n");
            }
            this->counter++;
            char msg[] = " ";
            if (strcmp(command, "Yes") == 0) {
                unsigned char *pkto = prepare_msg_packet(&size, msg, sizeof(msg), DELETE_Y, counter, this->shared_key);
                cm.send_packet(pkto, size);

            } else {
                unsigned char *pkto = prepare_msg_packet(&size, msg, sizeof(msg), DELETE_N, counter, this->shared_key);
                cm.send_packet(pkto, size);
            }

        } else if (opcode == LOGOUT) {

            handle_ack(pkt);
            cm.close_socket();
            if (this->shared_key != nullptr) {
                unoptimized_memset(this->shared_key, 0, this->key_size);
                free(this->shared_key);
            }
            exit(1);

        } else if (opcode == DOWNLOAD) {

            create_downloaded_file(pkt);
            printf("Download finished!\n");
            show_menu();

        } else if (opcode == CHUNK) {

            char path[] = "client_file/";
            string file_path = path;
            file_path += this->user;
            file_path += "/file/";
            file_path += this->file_name;
            char *filepath = &file_path[0];

            if (this->counter == UINT16_MAX - 2) //Check counter overflow
            {
                throw ExitException("Counter Exceeded\n");
            }
            this->counter++;
            this->counter = rcv_file(pkt, filepath, this->counter, this->shared_key, &this->cm);
            printf("Download finished!\n");
            show_menu();

        } else if (opcode == UPLOAD) {

            handle_ack(pkt);
            char path[] = "client_file/";
            string file_path = path;
            file_path += this->user;
            file_path += "/file/";
            file_path += this->file_name;
            char *filepath = &file_path[0];
            this->counter = send_file(filepath, opcode, this->counter, this->shared_key, &this->cm);

        } else {

            printf("Not a valid opcode\n");
            cm.close_socket();
            if (this->shared_key != nullptr) {
                unoptimized_memset(this->shared_key, 0, this->key_size);
                free(this->shared_key);
            }
            exit(1);
        }
        /* Clean packet */
        free(pkt);
    }
/* Exception handler */
    catch (Exception &e) {

        cerr << e.what();
        show_menu();

    } catch (ExitException &e) {

        cerr << e.what();
        cm.close_socket();
        if (this->shared_key != nullptr) {
            uint32_t siz;
            char msg[] = " ";
            unsigned char *pac;
            if (this->counter == UINT16_MAX)
                throw ExitException("Counter exceeded\n");
            this->counter++;
            pac = prepare_msg_packet(&siz, msg, sizeof(msg), ACK, counter, this->shared_key);
            cm.send_packet(pac, siz);
            unoptimized_memset(this->shared_key, 0, this->key_size);
            free(this->shared_key);

        }
        exit(1);
    }

}

/* Main menù */
void client::show_menu() {

    print_commands();

    char command[MAXCOMMANDSIZE];
    char *check = fgets(command, MAXCOMMANDSIZE, stdin);
    if (check == nullptr) {
        throw Exception("Error in fgets");
    }
    if (!strchr(command, '\n')) {
        printf("Error: command exceeding 30 characters\n");
        char c[2];
        while (c[0] != '\n') {
            check = fgets(c, 2, stdin);
            if (check == nullptr) {
                throw Exception("Error in fgets");
            }
        }
        show_menu();
    }

    command[strcspn(command, "\n")] = 0;

    try {
        /* Check if the command is in the right format */
        if (nameChecker(command, COMMAND)) {
            uint32_t size;
            if (strcmp(command, "!list") == 0) {

                /* Just something to encrypt */
                char msg[] = " ";

                if (this->counter == UINT16_MAX - 2) //Check counter overflow
                {
                    throw ExitException("Counter Exceeded\n");
                }
                this->counter++;

                /* List of files request */
                unsigned char *pkto = prepare_msg_packet(&size, msg, sizeof(msg), LIST, counter, this->shared_key);
                this->cm.send_packet(pkto, size);

            } else if (strcmp(command, "!download") == 0) {

                unsigned char *req = crt_generic_req(&size, DOWNLOAD);
                cm.send_packet(req, size);

            } else if (strcmp(command, "!upload") == 0) {

                unsigned char *req = crt_generic_req(&size, UPLOAD);
                cm.send_packet(req, size);

            } else if (strcmp(command, "!rename") == 0) {

                rename_file();

            } else if (strcmp(command, "!delete") == 0) {

                unsigned char *req = crt_generic_req(&size, DELETE);
                cm.send_packet(req, size);

            } else if (strcmp(command, "!logout") == 0) { // IMPLEMENT

                /* Something to encrypt */
                char msg[] = " ";

                uint32_t siz;

                if (this->counter == UINT16_MAX - 2) //Check counter overflow
                {
                    throw ExitException("Counter Exceeded\n");
                }
                this->counter++;

                unsigned char *pkto = prepare_msg_packet(&siz, msg, sizeof(msg), LOGOUT, this->counter,
                                                         this->shared_key);
                cm.send_packet(pkto, siz);

                printf("Bye!\n");

                unoptimized_memset(this->shared_key, 0, this->key_size);
                free(this->shared_key);

                cm.close_socket();

                exit(0);
            } else {

                printf("Command %s not found, please retry\n", command);
                show_menu();
            }
        } else {

            printf("Command format not valid, please use the format !command\n");
            show_menu();
        }
    }
        /* Exception Handler */
    catch (exception &e) {

        cerr << e.what();
        show_menu();
    }
}

/* Shows the list of files */
void client::show_list(unsigned char *pkt, int pos) {

    uint16_t list_size;

    if (this->counter == UINT16_MAX - 2) //Check counter overflow
    {
        throw ExitException("Counter Exceeded\n");
    }
    this->counter++;

    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t)); //counter
    pos += sizeof(uint16_t);
    count = ntohs(count);

    if (this->counter != count) { //counter check
        cerr << "counter errato";
    }

    memcpy(&list_size, pkt + pos, sizeof(list_size)); // list_size
    pos += sizeof(list_size);
    list_size = ntohs(list_size);

    unsigned char iv[IVSIZE]; // IV
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    crypto c = crypto(); //list
    unsigned char ct[list_size];
    memcpy(ct, pkt + pos, list_size);
    unsigned char pt[list_size];
    pos += list_size;
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);

    unsigned char tag[TAGSIZE]; //tag
    memcpy(tag, pkt + pos, TAGSIZE);

    /* Decryption */
    c.decrypt_message(ct, list_size, (unsigned char *) pkt, aad_size, tag, this->shared_key, iv, pt);

    printf("\nAvailable files:\n%s", pt);

}

/* Creates the request for download, upload, delete or rename a file */
unsigned char *client::crt_generic_req(uint32_t *size, uint8_t opcode) {

    printf("Inserisci file\n");
    char filename[MAXFILENAMESIZE];
    char *check1 = fgets(filename, MAXFILENAMESIZE, stdin);
    if (check1 == nullptr) {
        throw Exception("Error in fgets");
    }
    if (!strchr(filename, '\n')) {  //STDIN Buffer clean
        char c[2];
        while (c[0] != '\n') {
            check1 = fgets(c, 2, stdin);
            if (check1 == nullptr) {
                throw Exception("Error in fgets");
            }
        }
        throw Exception("Filename exceeding 30 characters");
    }

    for (int i = 0; i < MAXFILENAMESIZE; i++) {
        if (filename[i] == '\n') {
            filename[i] = '\0';
            break;
        }
    }

    /* Check if the filename is ok (it's done server-side too) */
    bool check = nameChecker(filename, FILENAME);
    if (!check) {
        throw Exception("Insert a correct filename format\n");
    }
    size_t filename_size = strlen(filename) + 1;

    if (opcode == DOWNLOAD) {
        FILE *f;
        string path = "client_file/";
        path = path + this->user + "/file/" + filename;
        f = fopen(path.c_str(), "rb");
        if (f) {
            fclose(f);
            throw Exception("File already existing in your folder!\n");
        }
    }

    /* Private variable because it has to keep it for
     * the next request */
    this->file_name = (char *) malloc(filename_size);
    if (this->file_name == NULL) {
        cerr << "Malloc return NULL";
        exit(1);
    }
    memcpy(this->file_name, &filename[0], filename_size);

    if (this->counter == UINT16_MAX - 2) //Check counter overflow
    {
        throw ExitException("Counter Exceeded\n");
    }

    this->counter++;
    unsigned char *packet = crt_request_pkt(filename, (int *) size, opcode, this->counter);
    return packet;
}

/* Creates the generic packet */
unsigned char *client::crt_request_pkt(char *filename, int *size, uint8_t opcode, uint16_t counter2) {

    crypto c = crypto();

    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) * 2;
    uint16_t ptext_size = strlen(filename) + 1;
    int pos = 0;
    int cipherlen;
    uint16_t n_counter = htons(counter2);
    *size = aad_size + IVSIZE + ptext_size + TAGSIZE;

    auto *pkt = (unsigned char *) malloc(*size);
    if (pkt == NULL) {
        cerr << "Malloc return NULL";
        exit(1);
    }

    unsigned char iv[IVSIZE];
    c.create_random_iv(iv);

    unsigned char tag[TAGSIZE];

    memcpy(pkt, &opcode, sizeof(uint8_t)); //OPCODE
    pos += sizeof(uint8_t);

    memcpy(pkt + pos, &n_counter, sizeof(uint16_t)); //Counter
    pos += sizeof(uint16_t);

    memcpy(pkt + pos, &ptext_size, sizeof(uint16_t)); //Plaintext size ( = Ciphertext size)
    pos += sizeof(uint16_t);

    memcpy(pkt + pos, iv, IVSIZE); //IV
    pos += IVSIZE;

    /* Encryption */
    cipherlen = c.encrypt_packet((unsigned char *) filename, strlen(filename) + 1,
                                 (unsigned char *) pkt, aad_size, shared_key, iv,
                                 (unsigned char *) pkt + pos, tag);

    pos += cipherlen;

    memcpy(pkt + pos, tag, TAGSIZE); //TAG
    pos += TAGSIZE;

    return pkt;
}

/* Stores the file */
void client::create_downloaded_file(unsigned char *pkt) {

    uint32_t ret;
    crypto c = crypto();
    int aad_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint16_t count;
    uint32_t file_size;
    int pos = sizeof(uint8_t);

    memcpy(&count, pkt + pos, sizeof(uint16_t)); // Counter
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter == UINT16_MAX - 2) // Check counter overflow
    {
        throw ExitException("Counter Exceeded\n");
    }
    this->counter++;
    if (counter != count) { //Counter check
        cerr << "Counter errato";
        exit(0);
    }

    memcpy(&file_size, pkt + pos, sizeof(uint32_t)); // File_size
    file_size = ntohl(file_size);
    pos += sizeof(uint32_t);

    unsigned char iv[IVSIZE]; // IV
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    unsigned char ctext[file_size]; // Ciphertext
    memcpy(ctext, pkt + pos, file_size);
    pos += file_size;

    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);

    unsigned char ptext[file_size + 1]; //Plaintext

    /* Decryption */
    c.decrypt_message(ctext, file_size, pkt, aad_len, tag,
                      this->shared_key, iv, ptext);

    /* String terminator necessary */
    ptext[file_size] = '\0';

    /* Client path construction */
    char path[] = "client_file/";
    string file_path = path;
    file_path += this->user;
    file_path += "/file/";
    file_path += this->file_name;
    char *filepath = &file_path[0];
    FILE *file = fopen(filepath, "wb");
    if (file == nullptr) {
        printf("Errore nella fopen\n");
        exit(-1);
    }

    /* Conversion check */
    size_t tmp = (uint32_t) fwrite(ptext, sizeof(unsigned char), file_size, file);
    if (tmp < UINT32_MAX) {
        ret = (uint32_t) tmp;
    } else {
        throw Exception("Something went wrong");
    }

    if (ret < file_size) {
        printf("Errore nella fwrite\n");
        exit(-1);
    }

    fclose(file);

    /* Clean up */
    unoptimized_memset(ptext, 0, file_size);

}

/* Handle the Server Hello message */
void client::server_hello_handler(unsigned char *pkt, int pos) {

    crypto c = crypto();
    int ret;

    uint16_t nonce_size; // Nonce_size
    memcpy(&nonce_size, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    nonce_size = ntohs(nonce_size);

    uint32_t cert_size; // Certificate_size
    memcpy(&cert_size, pkt + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    cert_size = ntohl(cert_size);

    uint32_t key_siz; // Key_size
    memcpy(&key_siz, pkt + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    key_siz = ntohl(key_siz);

    uint32_t sgnt_size; // Signature_size
    memcpy(&sgnt_size, pkt + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    sgnt_size = ntohl(sgnt_size);

    unsigned char snonce[nonce_size]; //Nonce
    memcpy(snonce, pkt + pos, nonce_size);
    pos += nonce_size;

    unsigned char cert[cert_size]; //Certificate
    memcpy(cert, pkt + pos, cert_size);
    pos += cert_size;

    unsigned char key[key_siz]; //Key
    memcpy(key, pkt + pos, key_siz);
    pos += key_siz;

    unsigned char sign[sgnt_size]; //Signature
    memcpy(sign, pkt + pos, sgnt_size);

    /* Deserialization of the certificate */
    BIO *bio = BIO_new(BIO_s_mem());
    ret = BIO_write(bio, cert, cert_size);
    if (ret == 0) {
        cerr << "errore in BIO_write";
        exit(1);
    }
    X509 *certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (certificate == nullptr) {
        cerr << "PEM_read_bio_X509 error";
        exit(1);
    }

    /* Check if the certificate is valid */
    bool b = c.verify_cert(certificate);
    if (!b) {
        cerr << "certificate not valid";
        exit(1);
    } else {
        printf("\nValid Certificate!\n");
    }

    pos = 0;

    /* What has to be verified */
    unsigned char to_verify[key_siz + nonce_size];
    memcpy(to_verify, key, key_siz);
    pos += key_siz;

    memcpy(to_verify + pos, this->nonce, nonce_size);

    /* Clean bio */
    BIO_free(bio);

    /* Key deserialization */
    bio = BIO_new(BIO_s_mem());
    ret = BIO_write(bio, key, key_siz);
    if (ret == 0) {
        cerr << "errore in BIO_write";
        exit(1);
    }
    EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (pubkey == nullptr) {
        cerr << "PEM_read_bio_PUBKEY error";
        exit(1);
    }

    /* Signature verification */
    b = c.verify_sign(sign, sgnt_size, to_verify, key_siz + nonce_size, X509_get_pubkey(certificate));
    if (!b) {
        cerr << "signature not valid";
        exit(1);
    } else {
        printf("\nValid Signature!\n\n");
    }

    /* Clean up */
    free(nonce);
    X509_free(certificate);
    BIO_free(bio);
    auth(snonce, pubkey);
}

void client::handle_ack(unsigned char *pkt) {

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

    if (this->counter != count) { //Counter check
        cerr << "Wrong counter!\n";
        exit(1);
    }

    uint16_t size_m; // Size of the ciphertext
    memcpy(&size_m, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    size_m = ntohs(size_m);

    crypto c = crypto();

    unsigned char iv[IVSIZE]; //IV
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    unsigned char ct[size_m]; //Ciphertext
    memcpy(ct, pkt + pos, size_m);
    pos += size_m;

    unsigned char tag[TAGSIZE]; //Tag
    memcpy(tag, pkt + pos, TAGSIZE);

    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char pt[size_m]; //Plaintext
    unsigned char aad[aad_size]; // AAD for AES_GCM
    memcpy(aad, pkt, aad_size);

    /* Decryption */
    c.decrypt_message(ct, size_m, aad, aad_size, tag, this->shared_key, iv, pt);

    printf("%s\n", pt);
}

/* Initialization of rename parameters */
void client::rename_file() {

    cout << "Rename - Which file?\n";

    char file_nam[MAXFILENAMESIZE];
    char *check = fgets(file_nam, MAXFILENAMESIZE, stdin);
    if (check == nullptr) {
        throw Exception("Error in fgets");
    }
    if (!strchr(file_nam, '\n')) { //STDIN Buffer clean
        char c[2];
        while (c[0] != '\n') {
            check = fgets(c, 2, stdin);
            if (check == nullptr) {
                throw Exception("Error in fgets");
            }
        }
        throw Exception("Filename exceeding 300 characters");
    }

    file_nam[strcspn(file_nam, "\n")] = 0;

    /* Check the correctness of the filename (it's done server side too) */
    if (nameChecker(file_nam, FILENAME)) {
        printf("Filename %s - ok, please specify a new filename\n", file_nam);

        char new_name[MAXFILENAMESIZE];
        check = fgets(new_name, MAXFILENAMESIZE, stdin);
        if (check == nullptr) {
            throw Exception("Error in fgets");
        }

        if (!strchr(new_name, '\n')) {
            char c[2];
            while (c[0] != '\n') {
                check = fgets(c, 2, stdin);
                if (check == nullptr) {
                    throw Exception("Error in fgets");
                }
            }
            throw Exception("Filename exceeding 30 characters");
        }

        new_name[strcspn(new_name, "\n")] = 0;

        /* Check the correctness of the filename (it's done server side too) */
        if (nameChecker(new_name, FILENAME)) {

            uint32_t size;

            /* Generation of rename packet */
            unsigned char *packet = prepare_filename_packet(RENAME, &size, file_nam, new_name);
            cm.send_packet(packet, size);

            printf("Rename request for file %s - sent\n waiting for response...\n", file_nam);

        } else {

            throw Exception("Filename not accepted, please use filename.extension format\n");
        }

    } else {

        throw Exception("Filename not accepted, please use filename.extension format\n");

    }

}

/* Generation of rename packet */
unsigned char *client::prepare_filename_packet(uint8_t opcode, uint32_t *size, char *file_nam, char *new_name) {

    uint16_t old_size = htons(strlen(file_nam));
    uint16_t new_size = htons(strlen(new_name));

    string temp; //Merge the two names as plaintext
    temp += file_nam;
    temp += new_name;
    int pt_size = temp.length();
    char pt[pt_size];
    strcpy(pt, temp.c_str());

    uint32_t ct_size = pt_size; //Ciphertext size

    int pkt_len = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t) + IVSIZE +
                  ct_size + TAGSIZE;
    unsigned char *pkt = (unsigned char *) malloc(pkt_len);
    if (pkt == NULL) {
        throw Exception("Malloc returned NULL");
    }
    *size = pkt_len;

    int pos = 0;

    memcpy(pkt, &opcode, sizeof(uint8_t));//opcode
    pos += sizeof(uint8_t);

    if (this->counter == UINT16_MAX - 2) //Check counter overflow
    {
        throw ExitException("Counter Exceeded\n");
    }

    this->counter++; //Counter
    int counter2 = counter;
    uint16_t count = htons(counter2);
    memcpy(pkt + pos, &count, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    memcpy(pkt + pos, &old_size, sizeof(uint16_t));//strlen old_name
    pos += sizeof(uint16_t);

    memcpy(pkt + pos, &new_size, sizeof(uint16_t));//strlen new_name
    pos += sizeof(uint16_t);

    uint32_t size_m = htonl(ct_size); //CipherText Size
    memcpy(pkt + pos, &size_m, sizeof(uint32_t));
    pos += sizeof(uint32_t);

    crypto c = crypto();

    unsigned char iv[IVSIZE];//IV
    c.create_random_iv(iv);
    memcpy(pkt + pos, iv, IVSIZE);
    pos += IVSIZE;

    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t);

    unsigned char ct[ct_size]; //Ciphertext

    unsigned char tag[TAGSIZE]; //TAG

    /* Encryption */
    c.encrypt_packet((unsigned char *) pt, pt_size, (unsigned char *) pkt, aad_size, this->shared_key, iv, ct, tag);

    memcpy(pkt + pos, ct, ct_size);
    pos += ct_size;
    memcpy(pkt + pos, tag, TAGSIZE);

    return pkt;
}


