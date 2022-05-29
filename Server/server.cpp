#include "server.h"

#pragma once
using namespace std;

server::server(int sock) {
    this->socket = sock;
    this->cm = new connection_manager(this->socket);
    this->counter = 0;
}

void server::check_file(char *pkt, uint8_t opcode) {
    int pos = 8;
    int count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    if (count != this->counter) {
        cerr << "Probable replay attack";
    }
    int name_size;
    memcpy(&name_size, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    name_size = ntohs(name_size);
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    unsigned char iv[iv_size];
    memcpy(iv, pkt + pos, iv_size);
    pos += iv_size;
    unsigned char ct[name_size];
    memcpy(ct, pkt + pos, name_size);
    pos += name_size;
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) * 2;
    unsigned char aad[aad_size];
    memcpy(aad, pkt, aad_size);
    unsigned char tag[16];
    memcpy(tag, pkt + pos, 16);
    crypto *c = new crypto();
    unsigned char pt[name_size - 16];
    c->decrypt_message(ct, name_size, aad, aad_size, tag, this->shared_key, iv, iv_size, pt);
    bool b = nameChecker((char *)pt, FILENAME);
    if (!b) {
        uint32_t *size;
        char msg[]="Inserisci un nome corretto";
        char* pkt= prepare_ack_packet(size,msg,sizeof(msg));
        this->cm->send_packet(pkt,*size);
        return;
    }
    bool a;
    a = file_opener((char *)pt, this->logged_user);
    if (!a) {
        uint32_t *size;
        char msg[]="File già esistente";
        char* pkt= prepare_ack_packet(size,msg,sizeof(msg));
        this->cm->send_packet(pkt,*size);
        return;
    }
    this->file_name=(char *)malloc(name_size-16);
    memcpy(file_name,pt,name_size-17);
    memcpy(file_name,"\0",1);
    uint32_t *size;
    char msg[]="Check eseguito correttamente";
    char* p= prepare_ack_packet(size,msg,sizeof(msg));
    this->cm->send_packet(p,*size);
    char *packt;
    packt = this->cm->receive_packet();
    int pos1 = 0;
    uint8_t opcode2;
    memcpy(&opcode2, pkt, sizeof(opcode2));//prelevo opcode
    //opcode = ntohs(opcode);
    pos += sizeof(opcode2);
    printf("OPCODE ricevuto: %d\n", opcode2);
    store_file(packt, opcode2);

}


/*void server::handle_req() {//TEST deserializza e gestisce il 1° packet dell'handshake con il server

    char *pkt = cm->receive_packet();

    //Andrea test
    //Deserializzazione
    int pos = 0;
    uint16_t us_size;
    uint16_t nonce_size;
    uint8_t opcode;

    
    memcpy(&opcode, pkt, sizeof(opcode));//prelevo opcode
    opcode = ntohs(opcode);
    pos+=sizeof(opcode);

    memcpy(&us_size, pkt+pos, sizeof(us_size)); //prelevo us_size inizializzo la variabile che dovrà contenerlo
    pos+=sizeof(us_size);
    us_size = ntohs(us_size);
    char username[us_size];

    memcpy(&nonce_size, pkt+pos, sizeof(nonce_size)); //prelevo nonce_size e inizializzo la variabile che dovrà contenerlo
    pos+=sizeof(nonce_size);
    nonce_size = ntohs(nonce_size);
    unsigned char nonce[nonce_size];

    memcpy(&username, pkt+pos, us_size);//prelevo l'username
    pos+=us_size;

    memcpy(&nonce, pkt+pos, nonce_size);//prelevo il nonce

    //Fine Deserializzazione

    printf("pacchetto: \n opcode: %d\n us_size: %d\n nonce_size: %d\n, username: %s\n nonce: %s\n" ,opcode,us_size, nonce_size, username, nonce);

    //test andrea
    printf("username ricevuto %s\n", username);
    char test[us_size];
    strcpy(test, username);

    if (strcmp(username, test) == 0){//username usato per testing metodi
        printf("Username - OK\n");
        cm->send_opcode(ACK);
        //close(sock);
        //exit(0);
        char *pkt = cm->receive_packet();//waits for a request from the client
        //chiama metodo con while true che si blocca in receive packet fino a che non ha ricevuto opcode logout
    }
    else{
        printf("Username - Error\n");
        close(this->socket);
        exit(1);
    }

}*/

server::~server() {
    cm->close_socket();
}

//Andrea

void server::handle_req() {

    char *pkt = cm->receive_packet();
    int pos = 0;
    uint8_t opcode;
    memcpy(&opcode, pkt, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    //Andrea test
    //Deserializzazione

    if (opcode == LIST) {//IMPLEMENT
        send_list();
    } else if (opcode == DOWNLOAD) {//IMPLEMENT

    } else if (opcode == UPLOAD) {//IMPLEMENT+
        check_file(pkt, pos);
        //store_file(pkt, opcode);
    } else if (opcode == RENAME) {//IMPLEMENT

    } else if (opcode == DELETE) {//IMPLEMENT

    } else if (opcode == LOGOUT) {//IMPLEMENT
        printf("Received logout request. Closing connections.\n Bye!\n");
        cm->close_socket();
        exit(0);
    } else if (opcode == ACK) {

    } else if (opcode == UPLOAD) {//IMPLEMENT

    } else if (opcode == RENAME) {//IMPLEMENT

    } else if (opcode == DELETE) {//IMPLEMENT

    } else if (opcode == LOGOUT) {//IMPLEMENT

    } else if (opcode == ACK) {

    } else if (opcode == CHELLO_OPCODE) {
        client_hello_handler(pkt, pos);
    } else {
        printf("Not a valid opcode\n");
        return;
    }

    return;
}

void server::client_hello_handler(char *pkt, int pos) {

    uint16_t us_size;
    uint16_t nonce_size;

    //Deserializzazione

    memcpy(&us_size, pkt + pos,
           sizeof(us_size)); //prelevo us_size inizializzo la variabile che dovrà contenerlo
    pos += sizeof(us_size);
    us_size = ntohs(us_size);
    char username[us_size];

    memcpy(&nonce_size, pkt + pos,
           sizeof(nonce_size)); //prelevo nonce_size e inizializzo la variabile che dovrà contenerlo
    pos += sizeof(nonce_size);
    nonce_size = ntohs(nonce_size);
    unsigned char nonce[nonce_size];

    memcpy(&username, pkt + pos, us_size);//prelevo l'username
    pos += us_size;

    memcpy(&nonce, pkt + pos, nonce_size);//prelevo il nonce

    //Fine Deserializzazione

    printf(" pacchetto: \n us_size: %d\n nonce_size: %d\n username: %s\n nonce: %s\n", us_size, nonce_size,
           username, nonce);

    //test andrea
    printf("username ricevuto %s\n", username);
    logged_user = username;

    if (strcmp(username, "test") == 0) {//username usato per testing metodi
        printf("Username - OK\n");
        uint32_t size;
        char *packet = prepare_ack_packet(&size);
        printf("Test dimensione ack packet: %d\n", size);
        cm->send_packet(packet, size);
        //close(sock);
        //exit(0);
        handle_req();//waits for a request from the client
        //chiama metodo con while true che si blocca in receive packet fino a che non ha ricevuto opcode logout
    } else {
        printf("Username - Error\n");
        close(this->socket);
        exit(1);
    }
}

char *server::prepare_ack_packet(uint32_t *size, char* msg, int msg_size) {
    int pos=0;
    uint8_t opcode = ACK;
    int iv_size=EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    int pkt_len=sizeof(opcode)+sizeof(uint16_t)+sizeof(uint16_t)+msg_size+16;
    char packet[pkt_len];
    *size = sizeof(opcode);
    memcpy(packet, &opcode, sizeof(opcode));
    pos+=sizeof(opcode);
    this->counter++;
    memcpy(packet+pos,&counter,sizeof(uint16_t));
    pos+=sizeof(uint16_t);
    uint16_t size_m=htons(msg_size);
    memcpy(packet+pos,&size_m,sizeof(uint16_t));
    pos+=sizeof(uint16_t);
    crypto *c=new crypto();
    unsigned char* iv=c->create_random_iv();
    memcpy(packet+pos,iv,iv_size);
    pos+=iv_size;
    int aad_size=sizeof(opcode)+sizeof(uint16_t)+sizeof(uint16_t);
    unsigned char ct[msg_size+16];
    unsigned char tag[16];
    c->encrypt_packet((unsigned char*)msg,msg_size,(unsigned char*)packet,aad_size,this->shared_key,iv,iv_size,ct,tag);
    return packet;

}
char *server::prepare_ack_packet(uint32_t *size) {
    char *packet;
    uint8_t opcode = ACK;
    *size = sizeof(opcode);
    memcpy(packet, &opcode, sizeof(opcode));

    return packet;

}

char *server::crt_pkt_download(char *file, int *size) {

    char *pkt = crt_file_pkt(file, size, DOWNLOAD, this->counter);
    this->counter++;
    return pkt;
}

void server::store_file(char *pkt, uint8_t opcode) {
    int pos = sizeof(uint8_t);
    int count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (count != this->counter) {
        cerr << "Probable replay attack";
    }
    uint32_t file_size;
    memcpy(&file_size, pkt + pos, sizeof(file_size));
    pos += sizeof(file_size);
    file_size = ntohs(file_size);
    int aad_size = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint16_t);
    unsigned char aad[aad_size];
    memcpy(aad, pkt, aad_size);
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    unsigned char iv[iv_size];
    memcpy(iv, pkt + pos, iv_size);
    pos += iv_size;
    unsigned char ct[file_size];
    memcpy(ct, pkt + pos, file_size);
    pos += file_size;
    unsigned char tag[16];
    memcpy(&tag, pkt + pos, 16);
    crypto *c = new crypto();
    size_t size=file_size-16;
    unsigned char pt[size];
    int ret;
    c->decrypt_message(ct, file_size, aad, aad_size, tag, this->shared_key,iv,iv_size,pt);
    char *path=CLIENT_PATH;
    string file_path = path;
    file_path += this->logged_user;
    path = &file_path[0];
    strcpy(path+strlen(path), reinterpret_cast<const char *>(pt));
    size_t len = strlen(path)-1;
    char * filePath = (char*)malloc(len);
    memcpy(filePath, path, len);
    FILE* file=fopen(this->file_name,"wb");
    ret=fwrite(pt,sizeof(unsigned char),size,file);
    if(ret<=0){
        cerr << "Errore nel scrivere il file";
    }
    fclose(file);
    free(filePath);
    uint32_t *siz;
    char msg[]="Upload completato";
    char* pac= prepare_ack_packet(siz,msg,sizeof(msg));
    this->cm->send_packet(pac,*siz);
}

void server::send_list() {
    //prepare packet and send it

    printf("start send list\n");

    uint8_t opcode = LIST;
    string temp = print_folder(SERVER_PATH);
    
    char content[temp.length()+1];
    strcpy(content, temp.c_str());


    printf("List:\n %s\n saved, trying to send it\n", content);//TEST

    uint16_t list_size = htons(sizeof(content)+1);
    uint32_t packet_size = sizeof(opcode)+sizeof(list_size)+list_size+1;
    int pos = 0;
    char pkt[packet_size];

    memcpy(pkt, &opcode, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    memcpy(pkt + pos, &list_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, content, list_size);

    cm->send_packet(pkt, packet_size);

    printf("list sent: size %d\n %s\n", list_size, content);//TEST
    handle_req();
}

string server::print_folder(char* path){//Takes all files and saves them into a variable
    
    DIR *dir;
    struct dirent* ent;
    string file_list;
    string file_path = path;
    file_path += logged_user;
    path = &file_path[0];

    printf("PATH: %s\n",path);//TEST

    int counter = 0;

    dir = opendir(path);
    if(dir){
        printf("Directory - OK\n");
    }
    else{
        printf("Directory NOT found\n");
        exit(-1);
    }

    //print all the files and directories within directory 
    while ((ent = readdir (dir)) != NULL) {
        char * sel_file = ent->d_name;
        printf("Examined file: %s\n", sel_file);
        if(nameChecker(sel_file, FILENAME)){
            string temp = string(sel_file);
            file_list += temp;
            file_list += "\n";
            counter++;
        }
    }
    if(counter == 0){
        file_list+="There are no files in this folder";
    }
    printf("Cosa ho salvato?\n%s", file_list.c_str());//TEST
    closedir(dir);

    return file_list;
}

//~Andrea
