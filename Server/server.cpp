#include "server.h"

using namespace std;

server::server(int sock)
{
    this->socket = sock;
    this->cm = new connection_manager(this->socket);
    this->counter = 0;
}

void server::check_file(char *pkt, uint8_t opcode)
{
/*
    int pos = 8;
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (count != this->counter)
    {
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
    c->decrypt_message(ct, name_size, aad, aad_size, tag, this->shared_key, iv, iv_size, pt);*/
    
    int pos = 8;
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    count = ntohs(count);
    
    pos += sizeof(uint16_t);
    if (count != this->counter)
    {
        cerr << "Probable replay attack";
    }
    uint16_t name_size;
    memcpy(&name_size, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    name_size = ntohs(name_size);
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    unsigned char iv[iv_size];
    memcpy(iv, pkt + pos, iv_size);
    pos += iv_size;
    
    int cipherlen = name_size + (16 - name_size%16);
    if (name_size % 16 == 0)
    	cipherlen += 16;
    
    unsigned char ct[cipherlen];
    
    memcpy(ct, pkt + pos, name_size);
    pos += name_size;
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) * 2;
    unsigned char aad[aad_size];
    memcpy(aad, pkt, aad_size);
    unsigned char tag[16];
    memcpy(tag, pkt + pos, 16);
    crypto *c = new crypto();
    unsigned char pt[name_size];
    	
    c->decrypt_message(ct, cipherlen, aad, aad_size, tag, this->shared_key, iv, iv_size, pt);
    
    bool b = nameChecker((char *)pt, FILENAME);
    if (!b)
    {
        uint32_t *size;
        char msg[] = "Inserisci un nome corretto";
        char *pkt = prepare_ack_packet(size, msg, sizeof(msg));
        this->cm->send_packet(pkt, *size);
        return;
    }
    bool a;
    a = file_opener((char *) pt, this->logged_user);
    if(opcode==UPLOAD) {
        if (!a) {
            uint32_t *size;
            char msg[] = "File già esistente";
            char *pkt = prepare_ack_packet(size, msg, sizeof(msg));
            this->cm->send_packet(pkt, *size);
            return;
        }
        this->file_name = (char *) malloc(name_size);
        memcpy(file_name, pt, name_size-1);
        memcpy(file_name+name_size-1, "\0", 1);
        uint32_t *size;
        char msg[] = "Check eseguito correttamente";
        char *p = prepare_ack_packet(size, msg, sizeof(msg));
        this->cm->send_packet(p, *size);
        char *packt;
        packt = this->cm->receive_packet();
        int pos1 = 0;
        uint8_t opcode2;
        memcpy(&opcode2, pkt, sizeof(opcode2)); // prelevo opcode
        // opcode = ntohs(opcode);
        pos += sizeof(opcode2);
        printf("OPCODE ricevuto: %d\n", opcode2);
        store_file(packt);
    }else if(opcode==DELETE){
        if(a){
            uint32_t *size;
            char msg[] = "File non esistente";
            char *pkt = prepare_ack_packet(size, msg, sizeof(msg));
            this->cm->send_packet(pkt, *size);
            return;
        }
        this->file_name = (char *) malloc(name_size);
        memcpy(file_name, pt, name_size - 1);
        memcpy(file_name+name_size-1, "\0", 1);
        delete_file();
    } else if(opcode == DOWNLOAD) {
    	if (!a) {
    		uint32_t size;
    		this->file_name = (char *) malloc(name_size);
        	memcpy(file_name, pt, name_size - 1);
       	memcpy(file_name+name_size-1, "\0", 1);
        	char* pkt = crt_file_pkt(file_name, (int*)&size, opcode, this->counter);
        	this->cm->send_packet(pkt, (int)size);
        	return;
    	}
    	else {
    	     uint32_t *size;
            char msg[] = "File non esistente";
            char *pkt = prepare_ack_packet(size, msg, sizeof(msg));
            this->cm->send_packet(pkt, *size);
            return;
    	}
    }
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

server::~server()
{
    cm->close_socket();
}

// Andrea

void server::handle_req()
{

    char *pkt = cm->receive_packet();
    int pos = 0;
    uint8_t opcode;
    memcpy(&opcode, pkt, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    // Andrea test
    // Deserializzazione

    if (opcode == LIST)
    {
        send_list();
        handle_req();
    }
    else if (opcode == DOWNLOAD)
    { // IMPLEMENT
    	check_file(pkt, opcode);
    }
    else if (opcode == UPLOAD)
    { // IMPLEMENT+
        check_file(pkt, opcode);
        // store_file(pkt, opcode);
    }
    else if (opcode == RENAME)
    { // IMPLEMENT
        if(rename_file(pkt, pos)) //Rename success
        {
            char *packet;
            uint8_t opcode = RENAME_ACK;
            memcpy(packet, &opcode, sizeof(opcode));
            cm->send_packet(packet, sizeof(opcode));
        }
        else //Rename failure
        {
            char *packet;
            uint8_t opcode = RENAME_NACK;
            memcpy(packet, &opcode, sizeof(opcode));
            cm->send_packet(packet, sizeof(opcode));
        }
        handle_req();
    }
    else if (opcode == DELETE)
    {

    }
    else if (opcode == LOGOUT)
    { // IMPLEMENT
        printf("Received logout request. Closing connections.\n Bye!\n");
        cm->close_socket();
        exit(0);
    }
    else if (opcode == ACK)
    {
    }
    else if (opcode == CHELLO_OPCODE)
    {
        client_hello_handler(pkt, pos);
    }
    else if (opcode== AUTH){
        auth(pkt,pos);
    }
    else
    {
        printf("Not a valid opcode\n");
        return;
    }

    return;
}

void server::client_hello_handler(char *pkt, int pos)
{

    uint16_t us_size;
    uint16_t nonce_size;

    // Deserializzazione

    memcpy(&us_size, pkt + pos, sizeof(us_size)); // prelevo us_size inizializzo la variabile che dovrà contenerlo
    pos += sizeof(us_size);
    us_size = ntohs(us_size);
    char username[us_size];

    memcpy(&nonce_size, pkt + pos, sizeof(nonce_size)); // prelevo nonce_size e inizializzo la variabile che dovrà contenerlo
    pos += sizeof(nonce_size);
    nonce_size = ntohs(nonce_size);
    unsigned char nonce[nonce_size];

    memcpy(&username, pkt + pos, us_size); // prelevo l'username
    pos += us_size;

    memcpy(&nonce, pkt + pos, nonce_size); // prelevo il nonce

    // Fine Deserializzazione

    printf(" pacchetto: \n us_size: %d\n nonce_size: %d\n username: %s\n nonce: %s\n", us_size, nonce_size,
           username, nonce);

    // test andrea
    printf("username ricevuto %s\n", username);
    logged_user = username;

    /*
    if (strcmp(username, "test") == 0)
    { // username usato per testing metodi
        printf("Username - OK\n");
        uint32_t size;
        char *packet = prepare_ack_packet(&size);
        printf("Test dimensione ack packet: %d\n", size);
        cm->send_packet(packet, size);
        // close(sock);
        // exit(0);
        handle_req(); // waits for a request from the client
        // chiama metodo con while true che si blocca in receive packet fino a che non ha ricevuto opcode logout
    }
    else
    {
        printf("Username - Error\n");
        close(this->socket);
        exit(1);
    }
     */
    server_hello(nonce);
}

char *server::prepare_ack_packet(uint32_t *size, char *msg, int msg_size)
{
    int pos = 0;
    uint8_t opcode = ACK;
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    int pkt_len = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t) + msg_size + 16;
    char packet[pkt_len];
    *size = pkt_len;
    memcpy(packet, &opcode, sizeof(opcode));
    pos += sizeof(opcode);
    this->counter++;
    uint16_t count=htons(counter);
    memcpy(packet + pos, &count, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    uint16_t size_m = htons(msg_size);
    memcpy(packet + pos, &size_m, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    crypto *c = new crypto();
    unsigned char *iv = c->create_random_iv();
    memcpy(packet + pos, iv, iv_size);
    pos += iv_size;
    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char ct[msg_size + 16];
    unsigned char tag[16];
    c->encrypt_packet((unsigned char *)msg, msg_size, (unsigned char *)packet, aad_size, this->shared_key, iv, iv_size, ct, tag);
    memcpy(packet+pos,ct,msg_size+16);
    pos+=msg_size+16;
    memcpy(packet+pos,tag,16);
    return packet;
}
char *server::prepare_ack_packet(uint32_t *size)
{
    char *packet;
    uint8_t opcode = ACK;
    *size = sizeof(opcode);
    memcpy(packet, &opcode, sizeof(opcode));

    return packet;
}

char *server::crt_pkt_download(char *file, int *size)
{

    char *pkt = crt_file_pkt(file, size, DOWNLOAD, this->counter);
    this->counter++;
    return pkt;
}

void server::store_file(char *pkt)
{
    int pos = sizeof(uint8_t);
    int count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (count != this->counter)
    {
        cerr << "Probable replay attack";
    }
    uint32_t file_size;
    memcpy(&file_size, pkt + pos, sizeof(file_size));
    pos += sizeof(file_size);
    file_size = ntohl(file_size);
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
    size_t size = file_size - 16;
    unsigned char pt[size];
    int ret;
    c->decrypt_message(ct, file_size, aad, aad_size, tag, this->shared_key, iv, iv_size, pt);
    char *path = CLIENT_PATH;
    string file_path = path;
    file_path += this->logged_user;
    path = &file_path[0];
    strcpy(path + strlen(path), this->file_name);
    size_t len = strlen(path) - 1;
    char *filePath = (char *)malloc(len);
    memcpy(filePath, path, len);
    FILE *file = fopen(filePath, "wb");
    ret = fwrite(pt, sizeof(unsigned char), size, file);
    if (ret <= 0)
    {
        cerr << "Errore nel scrivere il file";
    }
    fclose(file);
    free(filePath);
    uint32_t *siz;
    char msg[] = "Upload completato";
    char *pac = prepare_ack_packet(siz, msg, sizeof(msg));
    this->cm->send_packet(pac, *siz);
    free(this->file_name);
}

void server::send_list()
{
    // prepare packet and send it

    printf("start send list\n");

    uint8_t opcode = LIST;
    string temp = print_folder(SERVER_PATH);

    char content[temp.length() + 1];
    strcpy(content, temp.c_str());

    printf("List:\n %s\n saved, trying to send it\n", content); // TEST

    uint16_t list_size = htons(sizeof(content) + 1);
    uint32_t packet_size = sizeof(opcode) + sizeof(list_size) + list_size + 1;
    int pos = 0;
    char pkt[packet_size];

    memcpy(pkt, &opcode, sizeof(uint8_t));
    pos += sizeof(uint8_t);
    memcpy(pkt + pos, &list_size, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    memcpy(pkt + pos, content, list_size);

    cm->send_packet(pkt, packet_size);

    printf("list sent: size %d\n %s\n", list_size, content); // TEST
}

string server::print_folder(char *path)
{ // Takes all files and saves them into a variable

    DIR *dir;
    struct dirent *ent;
    string file_list;
    string file_path = path;
    file_path += logged_user;
    path = &file_path[0];

    printf("PATH: %s\n", path); // TEST

    int counter = 0;

    dir = opendir(path);
    if (dir)
    {
        printf("Directory - OK\n");
    }
    else
    {
        printf("Directory NOT found\n");
        exit(-1);
    }

    // print all the files and directories within directory
    while ((ent = readdir(dir)) != NULL)
    {
        char *sel_file = ent->d_name;
        printf("Examined file: %s\n", sel_file);
        if (nameChecker(sel_file, FILENAME))
        {
            string temp = string(sel_file);
            file_list += temp;
            file_list += "\n";
            counter++;
        }
    }
    if (counter == 0)
    {
        file_list += "There are no files in this folder";
    }
    printf("Cosa ho salvato?\n%s", file_list.c_str()); // TEST
    closedir(dir);

    return file_list;
}

void server::delete_file() {
    char *path = CLIENT_PATH;
    string file_path = path;
    file_path += this->logged_user;
    path = &file_path[0];
    strcpy(path + strlen(path), this->file_name);
    size_t len = strlen(path) - 1;
    char *filePath = (char *)malloc(len);
    memcpy(filePath, path, len);
    int ret;
    ret = remove(filePath);
    if (ret != 0)
    {
        cerr << "Errore nell'eliminare il file";
    }
    free(filePath);
    uint32_t *siz;
    char msg[] = "File eliminato";
    char *pac = prepare_ack_packet(siz, msg, sizeof(msg));
    this->cm->send_packet(pac, *siz);
    free(this->file_name);
}

int server::get_socket() {
	return this->socket;
}

bool server::rename_file(char* pkt, int pos) {
    uint16_t new_size;
    uint16_t old_size;

    // Deserializzazione

    memcpy(&old_size, pkt + pos, sizeof(old_size)); // prelevo old_size inizializzo la variabile che dovrà contenerlo
    pos += sizeof(old_size);
    old_size = ntohs(old_size);
    char filename[old_size];

    memcpy(&new_size, pkt + pos,
           sizeof(new_size)); // prelevo new_size e inizializzo la variabile che dovrà contenerlo
    pos += sizeof(new_size);
    new_size = ntohs(new_size);
    char newfilename[new_size];

    memcpy(&filename, pkt + pos, old_size); // prelevo l'old name
    pos += old_size;

    memcpy(&newfilename, pkt + pos, new_size); // prelevo il new name

    printf(" pacchetto: \n old_size: %d\n new_size: %d\n filename: %s\n newfilename: %s\n", old_size, new_size,
           filename, newfilename);

    // Fine Deserializzazione

    if (nameChecker(filename, FILENAME)) //Check if username format is correct
    {
        if (file_opener(filename, logged_user)) //Check if the file exists
        {
            if(file_renamer(newfilename, filename))
            {
                printf("Rename - OK");
                return true;
            }

            else
            {
                printf("Rename - Error");
                return false;
            }

        }
        else 
        {
            printf("file %s - Not Found.\n", filename);
            char *packet;
            uint8_t code = RENAME_NACK;
            memcpy(packet, &code, sizeof(code));
            cm->send_packet(packet, sizeof(code));
        }
    } 
    else 
    {
        printf("filename %s - Error. Format not valid\n", filename);
        char *packet;
        uint8_t code = RENAME_NACK;
        memcpy(packet, &code, sizeof(code));
        cm->send_packet(packet, sizeof(code));
    }
}

bool server::file_renamer(char* new_name, char* old_name){

    string newnamepath = SERVER_PATH; //    ../server_file/client/
    newnamepath += logged_user; //          ../server_file/client/username
    newnamepath += "/"; //                  ../server_file/client/username/
    newnamepath += new_name; //             ../server_file/client/username/newname.extension
    
    string oldnamepath = SERVER_PATH; //    ../server_file/client/
    oldnamepath += logged_user; //          ../server_file/client/username
    oldnamepath += "/"; //                  ../server_file/client/username/
    oldnamepath += old_name; //             ../server_file/client/username/oldname.extension

    old_name = &oldnamepath[0];
    new_name = &newnamepath[0];
    printf("old: %s\n new: %s\n", old_name, new_name);//TEST
	
	if (rename(old_name, new_name) != 0)
    {
        return false;
    }
	else
    {
        return true;
    }
		
}

void server::server_hello(unsigned char* nonce) {
    uint8_t opcode=SHELLO_OPCODE;
    crypto *c=new crypto();
    c->create_nonce(snonce);



    string cacert_file_name = "./server_file/server/Server_cert.pem";

    // open the file to sign:
    FILE *cacert_file = fopen(cacert_file_name.c_str(), "r");
    if(!cacert_file) { cerr << "Error: cannot open file '" << cacert_file_name << "' (file does not exist?)\n"; exit(1); }

    // get the file size:
    // (assuming no failures in fseek() and ftell())
    fseek(cacert_file, 0, SEEK_END);
    long int clear_size = ftell(cacert_file);
    fseek(cacert_file, 0, SEEK_SET);

    // read the plaintext from file:
    unsigned char* cert = (unsigned char*)malloc(clear_size);
    if(!cert) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
    int ret = fread(cert, 1, clear_size, cacert_file);
    if(ret < clear_size) { cerr << "Error while reading file '" << cacert_file_name << "'\n"; exit(1); }
    fclose(cacert_file);

    uint32_t cert_size=(uint32_t)clear_size;

    this->my_prvkey= c->dh_keygen();



    uint32_t key_size;
    //c->serialize_dh_pubkey(this->my_prvkey,key);
    BIO* bio=BIO_new(BIO_s_mem());
    ret= PEM_write_bio_PUBKEY(bio, my_prvkey);
    if (ret == 0) {
        cerr << "Error: PEM_write_bio_PUBKEY returned " << ret << "\n";
        exit(1);
    }

    printf("prima di bio\n");
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    printf("key %s\n",*bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    printf("len %zu:\n",bptr->length);
    char key[bptr->length];
    memcpy(key,bptr->data,bptr->length);
    printf("key %s:\n",key);
    BIO_free(bio);
    key_size=bptr->length;


    int sign_size=key_size+sizeof(nonce);
    printf("sign size: %d\n",sign_size);
    unsigned char* tosign=(unsigned char*)malloc(sign_size);
    int pos=0;
    memcpy(tosign,key,key_size);
    pos+=key_size;
    uint16_t  nonce_size=sizeof(nonce);
    memcpy(tosign+pos,nonce,nonce_size);
    printf("nonce %s\n",nonce);
    unsigned int *sgnt_size;
    printf("ciao: %s\n",tosign);
    unsigned char* sign=c->signn(tosign,sign_size,"./server_file/server/Server_key.pem",sgnt_size);
    printf("signature size: %d",*sgnt_size);
    uint32_t pkt_len=sizeof(opcode)+sizeof(uint16_t)+sizeof(uint32_t)*3+nonce_size+key_size+cert_size+(*sgnt_size);
    char pkt[pkt_len];
    printf("pktlen %d\n",pkt_len);
    printf("checkpoint1\n");
    pos=0;
    memcpy(pkt,&opcode,sizeof(opcode));
    pos+=sizeof(opcode);
    printf("pos %d\n",pos);
    uint16_t nonce_size_s=htons(nonce_size);
    memcpy(pkt+pos,&nonce_size_s,sizeof(uint16_t));
    pos+=sizeof(uint16_t);
    printf("pos %d\n",pos);
    uint32_t cert_size_s=htonl(cert_size);
    memcpy(pkt+pos,&cert_size_s,sizeof(uint32_t));
    pos+=sizeof(uint32_t);
    printf("pos %d\n",pos);
    uint32_t key_size_s=htonl(key_size);
    memcpy(pkt+pos,&key_size_s,sizeof(uint32_t));
    pos+=sizeof(uint32_t);
    printf("pos %d\n",pos);
    uint32_t sgnt_size_s=htonl(*sgnt_size);
    memcpy(pkt+pos,&sgnt_size_s,sizeof(uint32_t));
    pos+=sizeof(uint32_t);
    printf("pos %d\n",pos);
    memcpy(pkt+pos,snonce,nonce_size);
    pos+=nonce_size;
    printf("pos %d\n",pos);
    memcpy(pkt+pos,cert,cert_size);
    pos+=cert_size;
    printf("pos %d\n",pos);
    memcpy(pkt+pos,key,key_size);
    pos+=key_size;
    printf("pos %d\n",pos);
    memcpy(pkt+pos,sign,ntohl(sgnt_size_s));
    this->cm->send_packet(pkt,pkt_len);
    printf("checkpoint10\n");

}

void server::auth(char *pkt, int pos) {
    int ret;
    crypto *c=new crypto();
    uint32_t key_size;
    memcpy(&key_size,pkt+pos,sizeof(uint32_t));
    key_size= ntohl(key_size);
    pos+=sizeof(uint32_t);
    uint32_t sgnt_size;
    memcpy(&sgnt_size,pkt+pos,sizeof(uint32_t));
    pos+=sizeof(uint32_t);
    sgnt_size= ntohl(sgnt_size);
    unsigned char key[key_size];
    memcpy(key,pkt+pos,key_size);
    pos+=key_size;
    unsigned char sign[sgnt_size];
    memcpy(sign,pkt+pos,sgnt_size);
    BIO* bio= BIO_new(BIO_s_mem());
    ret=BIO_write(bio, key, key_size);
    if(ret==0){
        cerr << "errore in BIO_write";
        exit(1);
    }
    EVP_PKEY* pubkey=PEM_read_bio_PUBKEY( bio, NULL, NULL, NULL);
    if(pubkey==NULL){
        cerr<<"PEM_read_bio_PUBKEY error";
        exit(1);
    }
    BIO_free(bio);
    unsigned char to_verify[key_size+8];
    pos=0;
    memcpy(to_verify+pos,key,key_size);
    pos+=key_size;
    memcpy(to_verify+pos,this->snonce,8);
    string newnamepath = SERVER_PATH; //    ../server_file/client/
    newnamepath += logged_user; //          ../server_file/client/username
    newnamepath += "/"; //                  ../server_file/client/username/
    newnamepath += "pubkey.pem";
    char* path = &newnamepath[0];
    FILE * file;
    file=fopen(path,"rb");
    EVP_PKEY* user_pk= PEM_read_PUBKEY(file,NULL,NULL,NULL);
    bool b=c->verify_sign(sign,sgnt_size,to_verify,key_size+8,user_pk);
    if(!b){
        cerr << "signature not valid";
        exit(1);
    }
    EVP_PKEY_free(user_pk);
    unsigned char* g=c->dh_sharedkey(this->my_prvkey,pubkey,this->key_size);
    this->shared_key=c->key_derivation(g,*this->key_size);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(my_prvkey);
    uint32_t *pkt_len;
    char msg[]="Connection established";
    char* packet=prepare_ack_packet(pkt_len,msg,sizeof(msg));
    this->cm->send_packet(packet,*pkt_len);
    handle_req();
}

//~Andrea
