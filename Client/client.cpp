#include "client.h"
#include <openssl/rand.h>

using namespace std;

client::client() = default;;

client::client(char *username, int sock) {
    /*
    char addr[] = "127.0.0.1";
    // long dest_port = 49151;
    long dest_port = 6666;
    */
    this->user = new char[10];
    // this->username = username;
    memcpy((void *) this->user, (void *) username, sizeof(username));
    //int seed=atoi(username);
    /*
    srand(time(nullptr));
    long std_port=rand()%6000+43151;
    printf("porta: %li\n",std_port);*/
    this->cm =connection_manager(sock);
    this->counter = 0;

}

void client::send_clienthello() {
    crypto c =crypto();

    nonce=(unsigned char*)malloc(NONCESIZE);
    c.create_nonce(nonce);
    unsigned char *pkt = this->crt_pkt_hello();
    this->cm.send_packet(pkt, 23);

    /*if(this->cm->receive_ack()){
        char * test = new char[10];//TEST -> messa per non far andare il loop il client
        //cm->close_socket();//TEST
        return test;//TEST -> messa per non far andare il loop il client
    }*/


}

unsigned char *client::crt_pkt_hello() { // Creates first handshake packet
    // PACKET FORMAT: OPCODE - USERNAME_SIZE - NONCE_SIZE - USERNAME - NONCE

    uint16_t us_size = htons(strlen(user) + 1);
    uint16_t nonce_size = htons(sizeof(nonce));
    uint8_t opcode = CHELLO_OPCODE;
    int pos = 0;
    uint32_t pkt_len=23;
    auto* pkt=(unsigned char*)malloc(pkt_len);
    memcpy(pkt, &opcode, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    memcpy(pkt + pos, &us_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, &nonce_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, user, strlen(user) + 1);
    // pos += sizeof(user);
    pos += strlen(user) + 1;
    memcpy(pkt + pos, nonce, NONCESIZE);
    //free(nounce);
    return pkt;
}
/*
unsigned char *client::crt_pkt_upload(char *filename, uint32_t *size) {

    unsigned char *pkt = crt_file_pkt(filename, size, UPLOAD, this->counter);
    this->counter++;
    return pkt;
    // static char pkt[23];
    /* int pos1 = 0;
     int ret;
     crypto *c=new crypto();
     FILE *file;
     uint8_t opcode = htons(UPLOAD);
     int aad_size=sizeof(uint8_t)+sizeof(uint16_t)+sizeof(uint32_t);
     unsigned char start_packet[aad_size];

     file = fopen(filename, "rb");
     if (file == NULL) {
         printf("Errore nell'apertura del file\n");
         exit(-1);
     }
     fseek(file, 0L, SEEK_END);
     uint32_t file_size = ftell(file);
     fseek(file, 0L, SEEK_SET);
     memcpy(start_packet, &opcode, sizeof(uint8_t));
     pos1 += sizeof(uint8_t);
     memcpy(start_packet + pos1, &this.counter, sizeof(uint16_t));
     pos1 += sizeof(uint16_t);
     memcpy(start_packet + pos1, &file_size, sizeof(uint32_t));

     unsigned char* iv = c->create_random_iv();
     int IVSIZE = IVSIZE;

     unsigned char ciphertext[file_size+16];
     unsigned char tag[16];
     int cipherlen = c->encrypt_message(file,file_size,start_packet,aad_size,c->get_key(), iv, IVSIZE, ciphertext,tag);
     ret = fclose(file);
     if (ret != 0) {
         printf("Errore\n");
         exit(1);
     }
     char final_packet[aad_size+IVSIZE+file_size+16+16];
     int pos = 0;
     memcpy(final_packet, start_packet, aad_size);
     pos += aad_size;
     memcpy(final_packet+pos, iv, IVSIZE);
     pos += IVSIZE;
     memcpy(final_packet+pos, ciphertext, cipherlen);
     pos += cipherlen;
     memcpy(final_packet+pos, tag, 16);
     pos += 16;

     free(tag);
     free(ciphertext);
     free(start_packet);
     free(iv);

     *size = pos;
     return final_packet;*/
//}

void client::auth(unsigned char *nounce, EVP_PKEY *pubkey) {
    crypto c = crypto();
    EVP_PKEY *my_prvkey = c.dh_keygen();
    uint32_t key_siz;
    //c->serialize_dh_pubkey(this->my_prvkey,key);
    BIO *bio = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_PUBKEY(bio, my_prvkey);
    if (ret == 0) {
        cerr << "Error: PEM_write_bio_PUBKEY returned " << ret << "\n";
        exit(1);
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);;
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    char* key=(char *)malloc(bptr->length);
    memcpy(key, bptr->data, bptr->length);
    key_siz = bptr->length;
    uint sign_size = key_siz + sizeof(nounce);
    auto* tosign=(unsigned char *)malloc(sign_size);
    int pos = 0;
    memcpy(tosign, key, key_siz);
    pos += (int)key_siz;
    uint16_t nonce_size = NONCESIZE;
    memcpy(tosign + pos, nounce, nonce_size);
    unsigned int sgnt_size;
    //unsigned char* sign=c->signn(tosign,sign_size,"./server_file/server/Server_key.pem",&sgnt_size);
    unsigned char *sign = c.signn(tosign, sign_size, "./client_file/Alice/alice_privkey.pem", &sgnt_size);
    uint8_t opcode = AUTH;
    uint32_t pkt_len = sizeof(opcode) + sizeof(uint32_t) * 2 + key_siz + sgnt_size;
    auto* pkt=(unsigned char *)malloc(pkt_len);
    pos = 0;
    memcpy(pkt + pos, &opcode, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    uint32_t key_size_s = htonl(key_siz);
    memcpy(pkt + pos, &key_size_s, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    uint32_t sgnt_size_s = htonl(sgnt_size);
    memcpy(pkt + pos, &sgnt_size_s, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    memcpy(pkt + pos, key, ntohl(key_size_s));
    pos += (int)ntohl(key_size_s);
    memcpy(pkt + pos, sign, ntohl(sgnt_size_s));;
    unsigned char *g = c.dh_sharedkey(my_prvkey, pubkey, &this->key_size);
    this->shared_key = c.key_derivation(g, this->key_size);

    this->cm.send_packet(pkt, pkt_len);

    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(my_prvkey);
    BIO_free(bio);
    free(sign);
    free(tosign);
    free(key);
    //free(nounce);
}

client::~client() { this->cm.close_socket(); }

// Andrea Test

void client::print_commands() {
    printf("\nPlease select a command\n");
    printf("!help --> Show all available actions\n");
    printf("!list --> Show all files uploaded to the server\n");
    printf("!download --> Download a file from the server\n");
    printf("!upload --> Upload a file to the server\n");
    printf("!rename --> Rename a file stored into the server\n");
    printf("!delete --> Delete a file stored into the server\n");
    printf("!logout --> Disconnect from the server and close the application\n");
}

void client::handle_req() {
    unsigned char* pkt=this->cm.receive_packet();
    // Andrea test
    // Deserializzazione
    int pos = 0;
    uint8_t opcode;

    memcpy(&opcode, pkt, sizeof(opcode)); // prelevo opcode
    // opcode = ntohs(opcode);
    pos += sizeof(opcode);

    if (opcode == SHELLO_OPCODE) {
        server_hello_handler(pkt, pos);
    } else if (opcode == LIST) {
        printf("Received List\n");
        show_list(pkt, pos);
        show_menu();
    } else if (opcode == ACK) { // TEST
        handle_ack(pkt);
        show_menu();
        return; // TEST
    } else if (opcode == DOWNLOAD) {
        create_downloaded_file(pkt);
        show_menu();
    } else {
        printf("Not a valid opcode\n");
        cm.close_socket(); // TEST
        exit(1);            // TEST
    }
    free(pkt);
}

void client::show_menu() {

    print_commands();

    char *command=( char *)malloc(30);
    fgets(command, 30, stdin);
    command[strcspn(command, "\n")] = 0;

    if (nameChecker(command, COMMAND)) {
        uint32_t size;
        if (strcmp(command, "!list") == 0) {
            char msg[]="PAD";
            this->counter++;
            unsigned char* pkto= prepare_msg_packet(&size,msg,sizeof(msg),LIST,counter,this->shared_key);
            this->cm.send_packet(pkto,size);
            free(command);
        } else if (strcmp(command, "!download") == 0) { // IMPLEMENT
            unsigned char *req = crt_download_request(&size);
            cm.send_packet(req, size);
            free(command);

        } else if (strcmp(command, "!upload") == 0) { // IMPLEMENT
            free(command);
        } else if (strcmp(command, "!rename") == 0) {
            free(command);
            rename_file();
        } else if (strcmp(command, "!delete\n") == 0) {
            free(command);
            /*
            char namefile[] = "a.txt";
            char *pkt = crt_pkt_remove(namefile, sizeof(namefile), &size);
            this->cm.send_packet(pkt, size);
             */

        } else if (strcmp(command, "!logout") == 0) { // IMPLEMENT
            free(command);
            /*char *packet = prepare_req_packet(&size, LOGOUT);
            cm->send_packet(packet, size);*/

            printf("Bye!\n");
            cm.close_socket();
            exit(0);
        } else {

            printf("Command %s not found, please retry\n", command);
            free(command);
        }
    } else {
        free(command);
        printf("Command format not valid, please use the format !command\n");
    }
}
/*
void client::prepare_req_packet(uint8_t opcode) {

    int pos = 0;
    int pt_size = sizeof(uint8_t)+sizeof(uint16_t);
    int IVSIZE = IVSIZE;
    int packet_len = pt_size+IVSIZE+16+20;
    printf("packet_len in prepare %d\n",packet_len);
    char* packet=(char*)malloc(packet_len);
    printf("dopo malloc di packet_len\n");
    memcpy(packet, &opcode, sizeof(uint8_t));//opcode
    pos += sizeof(opcode);

    this->counter++; //Counter
    int counter2= counter;
    uint16_t count=htons(counter2);
    memcpy(packet+pos, &count, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    crypto c =crypto(); //IV
    unsigned char* iv = (unsigned char*)malloc(IVSIZE);
    c.create_random_iv(iv);
    memcpy(packet + pos, iv, IVSIZE);
    pos += IVSIZE;

    int aad_size = sizeof(opcode) + sizeof(uint16_t); // Tag 
    unsigned char* tag = (unsigned char*)malloc(16);
    unsigned char pt[]="PAD";
    unsigned char* ct_text=(unsigned char*)malloc(20);
    c.encrypt_packet(pt, 4, (unsigned char *)packet, aad_size, this->shared_key, iv, IVSIZE, ct_text, tag);
    printf("dopo encrypt\n");
    memcpy(packet+pos,ct_text,20);
    memcpy(packet+pos,tag,16);
    free(iv);
    free(ct_text);
    free(tag);
    printf("prima di send\n");
    cm.send_packet(packet, packet_len);
}
*/
unsigned char * client::prepare_list_req(uint32_t* size){
    // PACKET FORMAT: OPCODE - COUNTER - CPSIZE - IV - CIPHERTEXT - TAG)
    char msg[]="PAD";
    int msg_size=sizeof(msg);
    int pos = 0;
    uint8_t opcode = LIST;
    uint32_t pkt_len = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t)+IVSIZE + msg_size+16 + TAGSIZE;
    auto* packet=(unsigned char *)malloc(pkt_len);
    *size = pkt_len;
    memcpy(packet, &opcode, sizeof(opcode)); //OPCode
    pos += sizeof(opcode);

    this->counter++; //Counter
    int counter2=counter;
    uint16_t count=htons(counter2);
    memcpy(packet + pos, &count, sizeof(uint16_t));
    pos += sizeof(uint16_t);


    uint16_t size_m = htons(msg_size+16); //CipherText Size
    memcpy(packet + pos, &size_m, sizeof(uint16_t));
    pos += sizeof(uint16_t);


    crypto *c;
    c = new crypto(); //IV
    unsigned char iv[IVSIZE];
    /*RAND_poll();
    RAND_bytes(iv, IVSIZE);*/
    c->create_random_iv(iv);
    memcpy(packet + pos, iv, IVSIZE);
    pos += IVSIZE;


    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t); //CipherText & Tag
    int ct_size=ntohs(size_m);
    auto* ct = (unsigned char*)malloc(ct_size);
    unsigned char tag[TAGSIZE];
    c->encrypt_packet((unsigned char *)msg, ct_size-16, (unsigned char *)packet, aad_size, this->shared_key, iv, IVSIZE, ct, tag);
    memcpy(packet+pos,ct,ct_size);
    pos+=ct_size;
    memcpy(packet+pos,tag,16);

    //free(iv);
    free(ct);
    return packet;
}
void client::show_list(unsigned char *pkt, int pos) {

    uint16_t list_size;

    // Deserializzazione

    this->counter++; // Counter
    uint16_t count;
    memcpy(&count, pkt+pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter != count) {
        cerr << "counter errato";
    }

    memcpy(&list_size, pkt + pos, sizeof(list_size)); // list_size
    pos += sizeof(list_size);
    list_size = ntohs(list_size);

    unsigned char iv[IVSIZE];
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    crypto c =crypto(); //list
    auto* ct = (unsigned char*)malloc(list_size);
    memcpy(ct,pkt+pos,list_size);
    auto* pt = (unsigned char*)malloc(list_size);
    pos+=list_size;
    int aad_size= sizeof(uint8_t)+sizeof(uint16_t)+sizeof(uint16_t);
    unsigned char tag[TAGSIZE]; //tag
    memcpy(tag, pkt + pos, TAGSIZE);

    c.decrypt_message(ct, list_size, (unsigned char*)pkt, aad_size, tag, this->shared_key, iv, IVSIZE, pt);

    // Fine Deserializzazione

    printf("\nAvailable files:\n%s", pt);
    free(pt);
    free(ct);

}


unsigned char *client::crt_pkt_remove(char *namefile, int name_size, int *size) {
    int pos = 0;
    uint8_t opcode = DELETE;
    uint32_t pkt_len = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t) + name_size + 16+TAGSIZE;
    auto *packet=(unsigned char *)malloc(sizeof(pkt_len));
    *size = pkt_len;
    memcpy(packet, &opcode, sizeof(opcode));
    pos += sizeof(opcode);
    this->counter++;
    memcpy(packet + pos, &counter, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    uint16_t size_m = htons(name_size);
    memcpy(packet + pos, &size_m, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    crypto c = crypto();
    unsigned char iv[IVSIZE];
    c.create_random_iv(iv);
    memcpy(packet + pos, iv, IVSIZE);
    pos += IVSIZE;
    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t);
    auto* ct=(unsigned char *)malloc(name_size+16);
    unsigned char tag[TAGSIZE];
    c.encrypt_packet((unsigned char *) namefile, name_size, (unsigned char *) packet, aad_size, this->shared_key, iv,
                      IVSIZE, ct, tag);
    memcpy(packet + pos, ct, name_size + 16);
    pos += name_size + 16;
    memcpy(packet + pos, tag, TAGSIZE);
    free(ct);
    return packet;
}

unsigned char *client::crt_download_request(uint32_t *size) {
    printf("Inserisci file\n");
    char filename[31];
    fgets(filename, 31, stdin);

    for(int i=0;i<31;i++) {
        if (filename[i] == '\n') {
            filename[i] = '\0';
            break;
        }
    }

    bool check = nameChecker(filename, FILENAME);
    if (!check) {
        printf("Inserisci un nome corretto\n");
        return nullptr;
    }
    this->file_name = filename;
    this->counter++;
    //printf("prima di crt_req_pkt\n");
    unsigned char *packet = crt_request_pkt(filename, (int *) size, DOWNLOAD, this->counter, this->shared_key);
    return packet;
}

unsigned char *client::crt_request_pkt(char *filename, int *size, uint8_t opcode, uint16_t counter, unsigned char *shared_key) {

    crypto c=crypto();

    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) * 2;
    uint16_t ptext_size = strlen(filename)+1;
    //uint16_t ptext_size_n = htons(ptext_size);
    int pos = 0;
    int cipherlen;
    uint16_t n_counter = htons(counter);
    *size = aad_size + IVSIZE + ptext_size + 16;

    auto *pkt = (unsigned char *) malloc(*size);
    unsigned char iv[IVSIZE];
    c.create_random_iv(iv);
    unsigned char tag[TAGSIZE];
    //unsigned char* ciphertext = (unsigned char*)malloc(ptext_size+16);

    memcpy(pkt, &opcode, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    memcpy(pkt + pos, &n_counter, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, &ptext_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, iv, IVSIZE);
    pos += IVSIZE;


    cipherlen = c.encrypt_packet((unsigned char *) filename, strlen(filename) + 1,
                                  (unsigned char *) pkt, aad_size, shared_key, iv, IVSIZE,
                                  (unsigned char *) pkt + pos, tag);

    pos += cipherlen;
    memcpy(pkt + pos, tag, TAGSIZE);
    pos += TAGSIZE;
    
    //printf("pos a fine reqpkt, %d\n", pos);
    return pkt;
}

void client::create_downloaded_file(unsigned char *pkt) {

    int ret;

    crypto c= crypto();
    int aad_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);

    char *counter_pos = (char*)pkt + sizeof(uint8_t);
    char *size_pos = counter_pos + sizeof(uint16_t);
    char *iv_pos = size_pos + sizeof(uint32_t);
    char *ct_pos = iv_pos + IVSIZE;

    uint16_t h_counter;
    uint32_t h_size;

    memcpy(&h_counter, counter_pos, sizeof(uint16_t));
    h_counter = ntohs(h_counter);
    memcpy(&h_size, size_pos, sizeof(uint32_t));
    h_size = ntohl(h_size);

    int ct_len = h_size + (16 - h_size % 16);
    if (h_size % 16 == 0)
        ct_len += 16;

    char *tag_pos = ct_pos + ct_len;

    auto *ptext = (unsigned char *) malloc(h_size);

    c.decrypt_message((unsigned char *) ct_pos, ct_len,
                       (unsigned char *) pkt, aad_len,
                       (unsigned char *) tag_pos,
                       this->shared_key,
                       (unsigned char *) iv_pos, IVSIZE,
                       ptext);

    FILE *file = fopen(this->file_name, "wb");
    if (file == nullptr) {
        printf("Errore nella fopen\n");
        exit(-1);
    }

    ret = fwrite(ptext, sizeof(unsigned char), h_size, file);
    if (ret < h_size) {
        printf("Errore nella fwrite\n");
        exit(-1);
    }
    fclose(file);

#pragma optimize("", off);
    memset(ptext, 0, h_size);
#pragma optimize("", on);

    free(ptext);

}

void client::rename_file() {//Va testata

    cout << "Rename - Which file?\n";
    char* file_name=( char *)malloc(11);
    fgets(file_name, 11, stdin);

    file_name[strcspn(file_name, "\n")] = 0;

    if (nameChecker(file_name, FILENAME)) {
        printf("Filename %s - ok, please specify a new filename\n", file_name);

        char* new_name=(char *)malloc(11);
        fgets(new_name, 11, stdin);

        new_name[strcspn(new_name, "\n")] = 0;

        if (nameChecker(new_name, FILENAME)) {
            uint32_t size;
            unsigned char *packet = prepare_filename_packet(RENAME, &size, file_name, new_name);
            free(new_name);

            cm.send_packet(packet, size);

            printf("Rename request for file %s - sent\n waiting for response...\n", file_name);
            free(file_name);
            //--Receive and analyze server's response

            unsigned char *response;
            response = cm.receive_packet();
            uint8_t opcode;

            memcpy(&opcode, response, sizeof(opcode)); // prelevo opcode

            if (opcode ==
                RENAME_ACK)//renametest: devo rimandargli old_name e new_name per verificare, mi pare basti il counter - dubbio
            {
                printf("Rename - OK\n");
            } else {
                printf("Rename - FAIL\n");
            }
        } else {

            printf("Filename %s - not accepted, please use filename.extension format\n", new_name);
            free(new_name);
        }

    } else {
        printf("Filename %s - not accepted, please use filename.extension format\n", file_name);
        free(file_name);
    }

}

unsigned char *client::prepare_filename_packet(uint8_t opcode, uint32_t *size, char *file_name, char *new_name) {

    uint16_t old_size = htons(strlen(file_name) + 1);
    uint16_t new_size = htons(strlen(new_name) + 1);

    int pos = 0;
    uint32_t pkt_len=sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t) + strlen(file_name) + 1 + strlen(new_name) + 1;
    auto* pkt=(unsigned char *)malloc(pkt_len);

    memcpy(pkt, &opcode, sizeof(uint8_t));//opcode
    pos += sizeof(uint8_t);
    memcpy(pkt + pos, &old_size, sizeof(uint16_t));//strlen old_name
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, &new_size, sizeof(uint16_t));//strlen new_name
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, file_name, strlen(file_name) + 1);//old_name
    pos += strlen(file_name) + 1;
    memcpy(pkt + pos, new_name, strlen(new_name) + 1);//new_name

    *size = sizeof(pkt);

    return pkt;
}

void client::server_hello_handler(unsigned char *pkt, int pos) {
    crypto *c;
    c = new crypto();
    int ret;
    uint16_t nonce_size;
    memcpy(&nonce_size, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    nonce_size = ntohs(nonce_size);
    uint32_t cert_size;
    memcpy(&cert_size, pkt + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    cert_size = ntohl(cert_size);
    uint32_t key_siz;
    memcpy(&key_siz, pkt + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    key_siz = ntohl(key_siz);
    uint32_t sgnt_size;
    memcpy(&sgnt_size, pkt + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    sgnt_size = ntohl(sgnt_size);
    auto* snonce=(unsigned char*)malloc(nonce_size);
    memcpy(snonce, pkt + pos, nonce_size);
    pos += nonce_size;
    auto* cert=(unsigned char*)malloc(cert_size);
    memcpy(cert, pkt + pos, cert_size);
    pos += cert_size;
    auto* key=(unsigned char*)malloc(key_siz);
    memcpy(key, pkt + pos, key_siz);
    pos += key_siz;
    auto* sign=(unsigned char*)malloc(sgnt_size);
    memcpy(sign, pkt + pos, sgnt_size);
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
    bool b = c->verify_cert(certificate);
    if (!b) {
        cerr << "certificate not valid";
        exit(1);
    } else {
        printf("\nValid Certificate!\n");
    }
    pos = 0;
    auto* to_verify=(unsigned char*)malloc(key_siz+nonce_size);
    memcpy(to_verify, key, key_siz);
    pos += key_siz;
    memcpy(to_verify + pos, this->nonce, nonce_size);
    BIO_free(bio);
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
    b = c->verify_sign(sign, sgnt_size, to_verify, key_siz + nonce_size, X509_get_pubkey(certificate));
    free(nonce);
    if (!b) {
        cerr << "signature not valid";
        exit(1);
    } else {
        printf("\nValid Signature!\n");
    }
    X509_free(certificate);
    BIO_free(bio);
    free(cert);
    free(to_verify);
    free(sign);
    free(key);
    //free(snonce);
    auth(snonce, pubkey);

}

void client::handle_ack(unsigned char *pkt) {
    int pos = sizeof(uint8_t);
    this->counter++;
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter != count) {
        cerr << "counter errato";
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
    auto* ct=(unsigned char*)malloc(size_m);
    memcpy(ct, pkt + pos, size_m);
    pos += size_m;
    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
    auto* pt=(unsigned char*)malloc(size_m);
    auto* aad=(unsigned char*)malloc(aad_size);
    memcpy(aad, pkt, aad_size);
    c->decrypt_message(ct, size_m, aad, aad_size, tag, this->shared_key, iv, IVSIZE, pt);
    printf("%s\n", pt);
    free(aad);
    free(ct);
    free(pt);
}
