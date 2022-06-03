#include "server.h"

using namespace std;

server::server(int sock)
{
    this->socket = sock;
    cm = connection_manager(this->socket);
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
    unsigned char* iv = (unsigned char*)malloc(iv_size);
    memcpy(iv, pkt + pos, iv_size);
    pos += iv_size;
    
    int cipherlen = name_size + (16 - name_size%16);
    if (name_size % 16 == 0)
    	cipherlen += 16;
    
    unsigned char* ct = (unsigned char*)malloc(cipherlen);
    
    memcpy(ct, pkt + pos, name_size);
    pos += name_size;
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) * 2;
    unsigned char* aad = (unsigned char*)malloc(aad_size);
    memcpy(aad, pkt, aad_size);
    unsigned char tag[16];
    memcpy(tag, pkt + pos, 16);
    crypto *c = new crypto();
    unsigned char* pt = (unsigned char*)malloc(name_size);
    	
    c->decrypt_message(ct, cipherlen, aad, aad_size, tag, this->shared_key, iv, iv_size, pt);
    
    bool b = nameChecker((char *)pt, FILENAME);
    if (!b)
    {
        uint32_t *size;
        char msg[] = "Inserisci un nome corretto";
        char *pkt = prepare_ack_packet(size, msg, sizeof(msg));
        cm.send_packet(pkt, *size);
        return;
    }
    bool a;
    a = file_opener((char *) pt, this->logged_user);
    if(opcode==UPLOAD) {
        if (!a) {
            uint32_t *size;
            char msg[] = "File già esistente";
            char *pkt = prepare_ack_packet(size, msg, sizeof(msg));
            cm.send_packet(pkt, *size);
            return;
        }
        this->file_name = (char *) malloc(name_size);
        memcpy(file_name, pt, name_size-1);
        memcpy(file_name+name_size-1, "\0", 1);
        uint32_t *size;
        char msg[] = "Check eseguito correttamente";
        char *p = prepare_ack_packet(size, msg, sizeof(msg));
        cm.send_packet(p, *size);
        char *packt;
        packt = cm.receive_packet();
        int pos1 = 0;
        uint8_t opcode2;
        memcpy(&opcode2, pkt, sizeof(opcode2)); 
        pos += sizeof(opcode2);
        store_file(packt);
    }else if(opcode==DELETE){
        if(a){
            uint32_t *size;
            char msg[] = "File non esistente";
            char *pkt = prepare_ack_packet(size, msg, sizeof(msg));
            cm.send_packet(pkt, *size);
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
        	cm.send_packet(pkt, (int)size);
        	return;
    	}
    	else {
    	     uint32_t *size;
            char msg[] = "File non esistente";
            char *pkt = prepare_ack_packet(size, msg, sizeof(msg));
            cm.send_packet(pkt, *size);
            return;
    	}
    }
    free(pt);
    free(aad);
    free(ct);
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
    cm.close_socket();
}

// Andrea

void server::handle_req()
{

    char *pkt = cm.receive_packet();
    int pos = 0;
    uint8_t opcode;
    memcpy(&opcode, pkt, sizeof(uint8_t));
    pos += sizeof(uint8_t);

    // Opcode Handle

    if (opcode == LIST)
    {
        send_list(pkt);
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
    {
        if(rename_file(pkt, pos)) //Rename success
        {
            char *packet;
            uint32_t size;
            packet = prepare_renameAck_pkt(&size, RENAME_ACK);
            
            cm.send_packet(packet, sizeof(opcode));
        }
        else //Rename failure
        {
            char *packet;
            uint32_t size;
            packet = prepare_renameAck_pkt(&size, RENAME_NACK);
            
            cm.send_packet(packet, sizeof(opcode));
        }
        handle_req();
    }
    else if (opcode == DELETE)
    {

    }
    else if (opcode == LOGOUT)
    { // IMPLEMENT
        printf("Received logout request. Closing connections.\n Bye!\n");
        cm.close_socket();
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
    this->logged_user = (char*)malloc(us_size);
    memcpy(&nonce_size, pkt + pos, sizeof(nonce_size)); // prelevo nonce_size e inizializzo la variabile che dovrà contenerlo
    pos += sizeof(nonce_size);
    nonce_size = ntohs(nonce_size);

    unsigned char* nonce = (unsigned char*)malloc(nonce_size);
    memcpy(this->logged_user, pkt + pos, us_size); // prelevo l'username
    pos += us_size;
    memcpy(nonce, pkt + pos, nonce_size); // prelevo il nonce


    server_hello(nonce);
    free(nonce);
}

//Prepare Generic Ack Packet

char *server::prepare_ack_packet(uint32_t *size, char *msg, int msg_size) 
{
    // PACKET FORMAT: OPCODE - COUNTER - CPSIZE - IV - CIPHERTEXT - TAG)

    int pos = 0;
    uint8_t opcode = ACK;
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    uint32_t ct_size=msg_size;
    int pkt_len = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t)+iv_size + ct_size + 16;
    char* packet=(char *)malloc(pkt_len);
    *size = pkt_len;
    
    
    memcpy(packet, &opcode, sizeof(opcode)); //OPCode
    pos += sizeof(opcode);
    
    
    this->counter++; //Counter
    int counter2=counter;
    uint16_t count=htons(counter2);
    memcpy(packet + pos, &count, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    
    
    uint16_t size_m = htons(ct_size); //CipherText Size
    memcpy(packet + pos, &size_m, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    
    
    crypto *c = new crypto(); //IV
    unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm()));
    c->create_random_iv(iv);
    memcpy(packet + pos, iv, iv_size);
    pos += iv_size;


    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t); //CipherText & Tag
    unsigned char* ct = (unsigned char*)malloc(ct_size);
    unsigned char tag[16]; 
    c->encrypt_packet((unsigned char *)msg, msg_size, (unsigned char *)packet, aad_size, this->shared_key, iv, iv_size, ct, tag);
    memcpy(packet+pos,ct,ct_size);
    pos+=ct_size;
    memcpy(packet+pos,tag,16);

    free(iv);
    free(ct);
    return packet;
}


char *server::prepare_ack_packet(uint32_t *size) //TEST - UNUSED
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
    
    unsigned char* aad = (unsigned char*)malloc(aad_size);
    memcpy(aad, pkt, aad_size);
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_size);
    memcpy(iv, pkt + pos, iv_size);
    pos += iv_size;
    unsigned char* ct = (unsigned char*)malloc(file_size);;
    memcpy(ct, pkt + pos, file_size);
    pos += file_size;
    unsigned char tag[16];
    memcpy(&tag, pkt + pos, 16);
    crypto *c = new crypto();
    size_t size = file_size - 16;
    unsigned char* pt = (unsigned char*)malloc(size);
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
    cm.send_packet(pac, *siz);
    free(this->file_name);
    
    free(aad);
    free(iv);
    free(ct);
    free(pt);
}

//Prepare list packet and sends it

void server::send_list(char* pkt)
{
    // PACKET FORMAT: OPCODE - COUNTER - LIST_SIZE - IV - CIPHERTEXT - TAG

    //scompatta

    int pos = sizeof(uint8_t);

    this->counter++; // Counter
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter != count) {
        cerr << "counter errato";
    }

    int iv_size2 = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    unsigned char* iv2 = (unsigned char*)malloc(iv_size2);
    memcpy(iv2, pkt + pos, iv_size2);
    pos += iv_size2;

    unsigned char tag2[16];
    memcpy(tag2, pkt + pos, 16);

    crypto *c = new crypto();
    int aad_size2= sizeof(uint8_t)+sizeof(uint16_t);
    c->decrypt_message(NULL, 0, (unsigned char*)pkt, aad_size2, tag2, this->shared_key, iv2, iv_size2, NULL);

    //fine scompatta

    uint8_t opcode = LIST;
    string temp = print_folder(SERVER_PATH);

    char* content = (char*)malloc(temp.length() + 1);//Retrieve the list
    strcpy(content, temp.c_str());

    uint16_t list_size = htons(strlen(content) + 17);
    
    pos = 0;
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    uint32_t ct_size=strlen(content)+17;
    uint32_t packet_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t)+iv_size + ct_size + 16;
    char* packet = (char*)malloc(packet_size);

    memcpy(packet, &opcode, sizeof(uint8_t));//Opcode
    pos += sizeof(uint8_t);

    this->counter++; //Counter
    int counter2=counter;
    uint16_t count3=htons(counter2);
    memcpy(packet + pos, &count3, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    memcpy(packet + pos, &list_size, sizeof(uint16_t));//List(CipherText) Size
    pos += sizeof(uint16_t);
    
    
    unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm())); //IV
    c->create_random_iv(iv);
    memcpy(packet + pos, iv, iv_size);
    pos += iv_size;


    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t); //CipherText & Tag
    unsigned char* ct = (unsigned char*)malloc(ct_size);

    unsigned char* tag = (unsigned char*)malloc(16); 
    c->encrypt_packet((unsigned char *)content, strlen(content)+1, (unsigned char *)packet, aad_size, this->shared_key, iv, iv_size, ct, tag);
    memcpy(packet+pos,ct,ct_size);
    pos+=ct_size;
    memcpy(packet+pos,tag,16);

    cm.send_packet(packet, packet_size);
    
    free(iv);
    free(ct);
    free(content);
    free(iv2);
    
}

// Takes all files and saves them into a variable

string server::print_folder(char *path)
{ 

    DIR *dir;
    struct dirent *ent;
    string file_list;
    string file_path = path;
    file_path += logged_user;
    file_path += "/file";
    path = &file_path[0];

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

    closedir(dir);

    return file_list;
}

//Select a file and remove it, if it exists
//return error otherwise

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
        cerr << "DELETE - ERROR\n";
    }
    free(filePath);
    uint32_t *siz;
    char msg[] = "File Removed";
    char *pac = prepare_ack_packet(siz, msg, sizeof(msg));
    cm.send_packet(pac, *siz);
    free(this->file_name);
}

int server::get_socket() {
	return this->socket;
}

//Deserializes a rename packet and rename
//the file, if it exists

/*bool server::rename_file(char* pkt, int pos) {

    //RECEIVED PACKET FORMAT: OPCODE - COUNTER - OLD_NAME_SIZE - NEW_NAME_SIZE - IV - OLDNAME & NEWNAME - TAG

    uint16_t new_size;
    uint16_t old_size;

    // Deserializzazione

    memcpy(&old_size, pkt + pos, sizeof(old_size)); // Old_size
    pos += sizeof(old_size);
    old_size = ntohs(old_size);
    char filename[old_size];

    memcpy(&new_size, pkt + pos, sizeof(new_size)); // New_size
    pos += sizeof(new_size);
    new_size = ntohs(new_size);
    char newfilename[new_size];

    memcpy(&filename, pkt + pos, old_size); // Old name
    pos += old_size;

    memcpy(&newfilename, pkt + pos, new_size); // New name

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
}*/

bool server::rename_file(char* pkt, int pos) {

    //RECEIVED PACKET FORMAT: OPCODE - COUNTER - CIPHERTEXT_SIZE - OLD_NAME_SIZE - NEW_NAME_SIZE - IV - OLDNAME & NEWNAME - TAG

    uint16_t new_size;
    uint16_t old_size;
    uint16_t cipher_size;

    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());

    // Deserialization

    this->counter++; // Counter
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter != count) {
        cerr << "counter errato";
    }

    memcpy(&cipher_size, pkt + pos, sizeof(cipher_size)); // Cipher_size
    pos += sizeof(cipher_size);
    old_size = ntohs(cipher_size);
    unsigned char* ct = (unsigned char*)malloc(cipher_size);

    memcpy(&old_size, pkt + pos, sizeof(old_size)); // Old_size
    pos += sizeof(old_size);
    old_size = ntohs(old_size);
    char* filename = (char*)malloc(old_size);

    memcpy(&new_size, pkt + pos, sizeof(new_size)); // New_size
    pos += sizeof(new_size);
    new_size = ntohs(new_size);
    char* newfilename = (char*)malloc(new_size);

    crypto *c;  // IV
    c = new crypto();
    unsigned char* iv = (unsigned char*)malloc(iv_size);
    memcpy(iv, pkt + pos, iv_size);
    pos += iv_size;

    memcpy(ct, pkt + pos, cipher_size);
    pos += cipher_size;
    unsigned char tag[16];
    memcpy(tag, pkt + pos, 16);
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char* pt = (unsigned char*)malloc(cipher_size);
    unsigned char* aad = (unsigned char*)malloc(aad_size);
    memcpy(aad, pkt, aad_size);
    c->decrypt_message(ct, cipher_size, aad, aad_size, tag, this->shared_key, iv, iv_size, pt);
    printf("%s\n", pt);

    pos = 0;

    memcpy(filename, pt, old_size); // Old name
    pos += old_size;

    memcpy(newfilename, pt+pos, new_size); // New name

    // End Deserialization

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
            cm.send_packet(packet, sizeof(code));
        }
    } 
    else 
    {
        printf("filename %s - Error. Format not valid\n", filename);
        char *packet;
        uint8_t code = RENAME_NACK;
        memcpy(packet, &code, sizeof(code));
        cm.send_packet(packet, sizeof(code));
    }
    free(ct);
    free(iv);
    free(newfilename);
    free(filename);
    free(aad);
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
    this->snonce=(unsigned char*)malloc(8);
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

    BIO* bio=BIO_new(BIO_s_mem());
    ret= PEM_write_bio_PUBKEY(bio, my_prvkey);
    if (ret == 0) {
        cerr << "Error: PEM_write_bio_PUBKEY returned " << ret << "\n";
        exit(1);
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    char* key = (char*)malloc(bptr->length);
    memcpy(key,bptr->data,bptr->length);
    BIO_free(bio);
    key_size=bptr->length;

    int sign_size=key_size+sizeof(nonce);
    unsigned char* tosign=(unsigned char*)malloc(sign_size);
    int pos=0;
    memcpy(tosign,key,key_size);
    pos+=key_size;
    uint16_t  nonce_size=sizeof(nonce);
    memcpy(tosign+pos,nonce,nonce_size);
    unsigned int sgnt_size;
    unsigned char* sign=c->signn(tosign,sign_size,"./server_file/server/Server_key.pem",&sgnt_size);
    uint32_t pkt_len=sizeof(opcode)+sizeof(uint16_t)+sizeof(uint32_t)*3+nonce_size+key_size+cert_size+(sgnt_size);
    char* pkt = (char*)malloc(pkt_len);
    pos=0;
    memcpy(pkt,&opcode,sizeof(opcode));
    pos+=sizeof(opcode);
    uint16_t nonce_size_s=htons(nonce_size);
    memcpy(pkt+pos,&nonce_size_s,sizeof(uint16_t));
    pos+=sizeof(uint16_t);
    uint32_t cert_size_s=htonl(cert_size);
    memcpy(pkt+pos,&cert_size_s,sizeof(uint32_t));
    pos+=sizeof(uint32_t);
    uint32_t key_size_s=htonl(key_size);
    memcpy(pkt+pos,&key_size_s,sizeof(uint32_t));
    pos+=sizeof(uint32_t);
    uint32_t sgnt_size_s=htonl(sgnt_size);
    memcpy(pkt+pos,&sgnt_size_s,sizeof(uint32_t));
    pos+=sizeof(uint32_t);
    memcpy(pkt+pos,snonce,nonce_size);
    pos+=nonce_size;
    memcpy(pkt+pos,cert,cert_size);
    pos+=cert_size;
    memcpy(pkt+pos,key,key_size);
    pos+=key_size;
    memcpy(pkt+pos,sign,ntohl(sgnt_size_s));
    cm.send_packet(pkt,pkt_len);
    free(sign);
    free(key);
    
    handle_req();

}

void server::auth(char *pkt, int pos) {

    int ret;
    crypto *c=new crypto();
    uint32_t key_siz;
    memcpy(&key_siz,pkt+pos,sizeof(uint32_t));
    key_siz= ntohl(key_siz);
    pos+=sizeof(uint32_t);
    uint32_t sgnt_size;
    memcpy(&sgnt_size,pkt+pos,sizeof(uint32_t));
    pos+=sizeof(uint32_t);
    sgnt_size= ntohl(sgnt_size);
    unsigned char* key = (unsigned char*)malloc(key_siz);
    memcpy(key,pkt+pos,key_siz);
    pos+=key_siz;
    unsigned char* sign = (unsigned char*)malloc(sgnt_size);
    memcpy(sign,pkt+pos,sgnt_size);
    BIO* bio= BIO_new(BIO_s_mem());
    ret=BIO_write(bio, key, key_siz);
    if(ret==0){
        cerr << "errore in BIO_write";
        exit(1);
    }
    EVP_PKEY* pubkey=PEM_read_bio_PUBKEY( bio, NULL, NULL, NULL);
    if(pubkey==NULL){
        cerr<<"PEM_read_bio_PUBKEY error";
        exit(1);
    }
    unsigned char* to_verify = (unsigned char*)malloc(key_siz+8);
    pos=0;
    memcpy(to_verify+pos,key,key_siz);
    pos+=key_siz;
    memcpy(to_verify+pos,this->snonce,sizeof(snonce));
    string newnamepath = SERVER_PATH; //    ../server_file/client/
    newnamepath += logged_user; //          ../server_file/client/username
    newnamepath += "/"; //                  ../server_file/client/username/
    newnamepath += "pubkey";
    newnamepath += "/";
    newnamepath += "pubkey.pem";
    char* path = &newnamepath[0];
    FILE * file;
    file=fopen(path,"rb");
    EVP_PKEY* user_pk= PEM_read_PUBKEY(file,NULL,NULL,NULL);
    bool b=c->verify_sign(sign,sgnt_size,to_verify,key_siz+8,user_pk);
    if(!b){
        cerr << "signature not valid";
        exit(1);
    }
    EVP_PKEY_free(user_pk);
    unsigned char* g=c->dh_sharedkey(this->my_prvkey,pubkey,&this->key_size);
    this->shared_key=c->key_derivation(g,this->key_size);
    uint32_t pkt_len;
    char msg[]="Connection established";
    char* packet=prepare_ack_packet(&pkt_len,msg,sizeof(msg));
    cm.send_packet(packet,pkt_len);
    BIO_free(bio);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(my_prvkey);
    handle_req();
    
    free(key);
    free(sign);
    free(to_verify);
}

//Serializes a rename ACK-NACK packet

char* server::prepare_renameAck_pkt(uint32_t *size, uint8_t opcode){

    // PACKET FORMAT: OPCODE - COUNTER (- IV - TAG)

    int pos = 0;
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    int pkt_len = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t)/*+iv_size*/;
    //uint32_t ct_size=msg_size;
    
    char* packet=(char *)malloc(pkt_len);
    *size = pkt_len;
    
    memcpy(packet, &opcode, sizeof(opcode)); //OPCode
    pos += sizeof(opcode);

    this->counter++; //Counter
    int counter2=counter;
    uint16_t count=htons(counter2);
    memcpy(packet + pos, &count, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    /*crypto *c = new crypto(); //IV
    unsigned char iv[EVP_CIPHER_iv_length(EVP_aes_128_gcm())];
    c->create_random_iv(iv);
    memcpy(packet + pos, iv, iv_size);*/

    return packet;

}

//~Andrea
