#include "server.h"
using namespace std;
//char SERVER_PATH[]="server_file/client/";
server::server(int sock)
{
    this->socket = sock;
    cm = connection_manager(this->socket);
    this->counter = 0;
}

void server::check_file(unsigned char* pkt, uint8_t opcode)
{
    int pos = sizeof(uint8_t);
    uint16_t count;
    memcpy(&count, pkt + pos, sizeof(uint16_t));
    if (this->counter == UINT16_MAX)
    	throw ExitException("Counter exceeded\n");
    	
    this->counter++;
    count = ntohs(count);

    pos += sizeof(uint16_t);
    if (count != this->counter)
    {
        throw Exception("Counter errato\n");
    }
    uint16_t name_size;
    memcpy(&name_size, pkt + pos, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    name_size = ntohs(name_size);
    /*int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm()); //TEST
    unsigned char* iv = (unsigned char*)malloc(iv_size);*/
    unsigned char iv[IVSIZE];
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    int cipherlen = name_size;

    unsigned char* ct = (unsigned char*)malloc(cipherlen);

    memcpy(ct, pkt + pos, name_size);
    pos += name_size;
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) * 2;
    /*unsigned char* aad = (unsigned char*)malloc(aad_size);
    memcpy(aad, pkt, aad_size);*/
    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);
    crypto *c = new crypto();
    unsigned char* pt = (unsigned char*)malloc(name_size);

    c->decrypt_message(ct, cipherlen, pkt, aad_size, tag, this->shared_key, iv, pt);
    bool b = nameChecker((char *)pt, FILENAME);
    if (!b)
    {
        uint32_t size;
        char msg[] = "Inserisci un nome corretto";
    	if (this->counter == UINT16_MAX)
    		throw ExitException("Counter exceeded\n");
    	
        this->counter++;
        unsigned char* pkto = prepare_msg_packet(&size,msg,sizeof(msg),ACK,this->counter,this->shared_key);
        cm.send_packet(pkto, size);
        return;
    }
    bool a;
    a = file_opener((char *) pt, this->logged_user);
    if(a or (opcode==UPLOAD)) {

        char path[] = "server_file/client/";
        string file_path = path; // ../server_file/client/
        file_path += this->logged_user;   // ../server_file/client/Alice
        file_path += "/file/"; // ../server_file/client/Alice/file/
        file_path += (char*)pt; // ../server_file/client/Alice/file/filename.extension
        size_t len = file_path.length() + 1;
        this->file_name=(char *)malloc(len);
        memcpy(this->file_name,&file_path[0],len);
    }
    if(opcode==UPLOAD) {
        if (a) {
            uint32_t size;
            char msg[] = "File già esistente";
            if (this->counter == UINT16_MAX)
    		throw ExitException("Counter exceeded\n");
            this->counter++;
            unsigned char* pkto = prepare_msg_packet(&size, msg, sizeof(msg),ACK,counter,this->shared_key);
            cm.send_packet(pkto, size);
            return;
        }
        uint32_t size;
        char msg[] = "File not existing in the sever: OK\n";
        if (this->counter == UINT16_MAX)
    		throw ExitException("Counter exceeded\n");
        this->counter++;
        unsigned char *p = prepare_msg_packet(&size, msg, sizeof(msg),UPLOAD,counter,this->shared_key);
        cm.send_packet(p, size);
    }
    else if(opcode==DELETE)
    {
        if(!a)
        {
            cerr << "DELETE - FILE NOT FOUND\n";
            char msg[] = "DELETE - FILE NOT FOUND\n";
            unsigned char *pac;
            uint32_t siz;
            if (this->counter == UINT16_MAX)
    		throw ExitException("Counter exceeded\n");
            this->counter++;
            pac = prepare_msg_packet(&siz, msg, sizeof(msg), ACK, counter, this->shared_key);        
            cm.send_packet(pac, siz);
        }else {
            this->file_name = (char *) malloc(name_size);
            memcpy(file_name, pt, name_size - 1);
            memcpy(file_name + name_size - 1, "\0", 1);
            delete_file();
        }
    }
    else if(opcode == DOWNLOAD) 
    {
    	if (a) {
        	this->counter= send_file(this->file_name,opcode,this->counter,this->shared_key,&this->cm);
            free(this->file_name);
        	return;
    	}
    	else {
    	     printf("File non esistente\n");
    	     uint32_t size;
            char msg[] = "File non esistente";
            if (this->counter == UINT16_MAX)
    		throw ExitException("Counter exceeded\n");
            this->counter++;
            unsigned char* pkto= prepare_msg_packet(&size,msg,sizeof(msg),ACK,this->counter,this->shared_key);
            cm.send_packet(pkto, size);
            return;
    	}
    }
    free(pt);
    //free(aad);
    free(ct);
}

server::~server()
{
    cm.close_socket();
}

// Andrea

void server::handle_req()
{
    try {
        unsigned char *pkt = cm.receive_packet();
        int pos = 0;
        uint8_t opcode;
        memcpy(&opcode, pkt, sizeof(uint8_t));
        pos += sizeof(uint8_t);
        // Opcode Handle

        if (opcode == LIST) {
            handle_list(pkt);
            uint32_t size;
            if (this->counter == UINT16_MAX)
    		throw ExitException("Counter exceeded\n");
            this->counter++;
            char s[] = "server_file/client/";
            string temp = print_folder(s);
            int msg_size = temp.length() + 1;
            char msg[msg_size];//Retrieve the list
            strcpy(msg, temp.c_str());
            unsigned char *pkto = prepare_msg_packet(&size, msg, msg_size, LIST, this->counter, this->shared_key);
            this->cm.send_packet(pkto, size);
        } else if (opcode == DOWNLOAD) { // IMPLEMENT
            check_file(pkt, opcode);
        } else if (opcode == UPLOAD) { // IMPLEMENT+
            check_file(pkt, opcode);
            // store_file(pkt, opcode);
        } else if (opcode == UPLOAD2) {
            store_file(pkt);
        } else if (opcode == CHUNK) {
            if (this->counter == UINT16_MAX)
    		throw ExitException("Counter exceeded\n");
            this->counter++;
            this->counter = rcv_file(pkt, this->file_name, this->counter, this->shared_key, &this->cm);
        } else if (opcode == RENAME) {
            if (rename_file(pkt, pos)) //Rename success
            {
                unsigned char *packet;
                uint32_t size;
                char msg[] = "Rename - OK\n";
                if (this->counter == UINT16_MAX)
    			throw ExitException("Counter exceeded\n");
                this->counter++;
                packet = prepare_msg_packet(&size, msg, sizeof(msg), ACK, counter, this->shared_key);
                cm.send_packet(packet, size);
            } else //Rename failure
            {
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
        } else if (opcode == LOGOUT) { // IMPLEMENT
            printf("[-] Client disconnected :(\n");
            cm.close_socket();

            unoptimized_memset(this->shared_key, 0, this->key_size);

            free(this->shared_key);
            exit(0);
        } else if (opcode == ACK) {
        } else if (opcode == CHELLO_OPCODE) {
            client_hello_handler(pkt, pos);
        } else if (opcode == AUTH) {
            auth(pkt, pos);
        } else {
            printf("Not a valid opcode\n");
            return;
        }

        return;
    }catch(Exception &e){
        unsigned char *packet;
        uint32_t size;
        //this->counter++;
        packet = prepare_msg_packet(&size, (char *)e.what(), sizeof(e.what()), ACK, counter, this->shared_key);
        cm.send_packet(packet, size);
    }catch (ExitException &e){
        unsigned char *packet;
        uint32_t size;
        //this->counter++;
        packet = prepare_msg_packet(&size, (char *)e.what(), sizeof(e.what()), ACK, counter, this->shared_key);
        cm.send_packet(packet, size);
        cm.close_socket();
        exit(1);
    }
}

void server::client_hello_handler(unsigned char* pkt, int pos)
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

    unsigned char nonce[NONCESIZE];
    memcpy(this->logged_user, pkt + pos, us_size); // prelevo l'username
    pos += us_size;
    memcpy(nonce, pkt + pos, nonce_size); // prelevo il nonce


    server_hello(nonce);
}


/*
unsigned char *server::crt_pkt_download(char *file, uint32_t *size)
{

    unsigned char* pkt = crt_file_pkt(file, size, DOWNLOAD, this->counter, this->shared_key);
    this->counter++;
    return pkt;
}
 */

void server::store_file(unsigned char* pkt)
{
    uint32_t ret;
    crypto c= crypto();
    int aad_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
    uint16_t count;
    uint32_t file_size;
    int pos=sizeof(uint8_t);
    memcpy(&count, pkt+pos, sizeof(uint16_t));
    pos+=sizeof(uint16_t);
    count = ntohs(count);
    if (this->counter == UINT16_MAX)
    			throw ExitException("Counter exceeded\n");
    this->counter++;
    if(counter!=count){
        throw Exception("Counter errato\n");
    }
    memcpy(&file_size, pkt+pos, sizeof(uint32_t));
    file_size = ntohl(file_size);
    pos+=sizeof(uint32_t);
    unsigned char iv[IVSIZE];
    memcpy(iv,pkt+pos,IVSIZE);
    pos+=IVSIZE;
    unsigned char ctext[file_size];
    memcpy(ctext, pkt+pos,file_size);
    pos+=file_size;
    unsigned char tag[TAGSIZE];
    memcpy(tag,pkt+pos,TAGSIZE);
    unsigned char ptext[file_size+1];
    c.decrypt_message(ctext, file_size,
                      pkt, aad_len,
                      tag,
                      this->shared_key,
                      iv,
                      ptext);
    ptext[file_size]='\0';
    FILE *file = fopen(this->file_name, "wb");
    if (file == nullptr) {
        throw Exception("Error in fopen\n");
    }
    ret =(uint32_t) fwrite(ptext, sizeof(unsigned char), file_size, file);
    if (ret < file_size) {
        throw Exception("Error in fwrite\n");
    }
    fclose(file);


    unoptimized_memset(ptext, 0, file_size);

    uint32_t siz;
    char msg[] = "Upload completato";
    if (this->counter == UINT16_MAX)
    	throw ExitException("Counter exceeded\n");
    this->counter++;
    unsigned char *pac = prepare_msg_packet(&siz,msg,sizeof(msg),ACK,this->counter,this->shared_key);
    cm.send_packet(pac, siz);
    free(this->file_name);
}

//Prepare list packet and sends it
void server::handle_list(unsigned char* pkt){

    //int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    int pos = sizeof(uint8_t);
    if (this->counter == UINT16_MAX)
    	throw ExitException("Counter exceeded\n");
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
    unsigned char* ct=(unsigned char*)malloc(size_m);
    memcpy(ct, pkt + pos, size_m);
    pos += size_m;
    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char* pt=(unsigned char*)malloc(size_m);
    unsigned char* aad=(unsigned char*)malloc(aad_size);
    memcpy(aad, pkt, aad_size);
    c->decrypt_message(ct, size_m, aad, aad_size, tag, this->shared_key, iv, pt);
    free(aad);
    free(ct);
    free(pt);
}
unsigned char *server::prepare_list_packet(int *size)
{
    /*
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
    unsigned char* ct_text=(unsigned char*)malloc(20);
    memcpy(ct_text, pkt + pos, 20);
    pos+=20;
    unsigned char* tag2=(unsigned char*)malloc(16);
    memcpy(tag2, pkt + pos, 16);
    crypto *c = new crypto();
    int aad_size2= sizeof(uint8_t)+sizeof(uint16_t);
    unsigned char* pt_text=(unsigned char*)malloc(20);
    c->decrypt_message(ct_text, 20, (unsigned char*)pkt, aad_size2, tag2, this->shared_key, iv2, iv_size2, pt_text);
    printf("ptext %s\n",pt_text);
    free(tag2);
    free(iv2);
    free(pt_text);
    free(ct_text);
    //fine scompatta

    uint8_t opcode = LIST;
    string temp = print_folder(SERVER_PATH);
    int content_size=temp.length() + 1;
    char* content = (char*)malloc(content_size);//Retrieve the list
    strcpy(content, temp.c_str());
    
    int pos = 0;
    int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    uint16_t ct_size=content_size+16;
    int packet_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t)+iv_size + ct_size + 16;
    unsigned char* packet = (unsigned char*)malloc(packet_size);

    memcpy(packet, &opcode, sizeof(uint8_t));//Opcode
    pos += sizeof(uint8_t);

    this->counter++; //Counter
    int counter2=counter;
    uint16_t count3=htons(counter2);
    memcpy(packet + pos, &count3, sizeof(uint16_t));
    pos += sizeof(uint16_t);
    ct_size=htons(ct_size);
    memcpy(packet + pos, &ct_size, sizeof(uint16_t));//List(CipherText) Size
    pos += sizeof(uint16_t);
    unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm())); //IV
    c->create_random_iv(iv);
    memcpy(packet + pos, iv, iv_size);
    pos += iv_size;

    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t); //CipherText & Tag
    unsigned char* ct = (unsigned char*)malloc(ntohs(ct_size));

    unsigned char* tag = (unsigned char*)malloc(16); 
    c->encrypt_packet((unsigned char *)content, content_size, (unsigned char *)packet, aad_size, this->shared_key, iv, iv_size, ct, tag);
    memcpy(packet+pos,ct,ntohs(ct_size));
    pos+=ntohs(ct_size);
    memcpy(packet+pos,tag,16);
    
    free(ct);
    
    free(content);

    cm.send_packet(packet, packet_size);
    */
    uint8_t opcode = LIST;
    char s[]="server_file/client/";
    string temp = print_folder(s);
    int msg_size=temp.length() + 1;
    char* msg = (char*)malloc(msg_size);//Retrieve the list
    strcpy(msg, temp.c_str());
    int pos = 0;
    //int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_gcm()); TEST
    uint32_t ct_size=msg_size;
    int pkt_len = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t)+IVSIZE + ct_size + 16;
    unsigned char* packet=(unsigned char *)malloc(pkt_len);
    *size = pkt_len;
    memcpy(packet, &opcode, sizeof(opcode)); //OPCode
    pos += sizeof(opcode);

    if (this->counter == UINT16_MAX)
    	throw ExitException("Counter exceeded\n");
    this->counter++; //Counter
    int counter2=counter;
    uint16_t count=htons(counter2);
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


    int aad_size = sizeof(opcode) + sizeof(uint16_t) + sizeof(uint16_t); //CipherText & Tag
    unsigned char ct[ct_size];
    unsigned char tag[TAGSIZE];
    c->encrypt_packet((unsigned char *)msg, msg_size, (unsigned char *)packet, aad_size, this->shared_key, iv, ct, tag);
    memcpy(packet+pos,ct,ct_size);
    pos+=ct_size;
    memcpy(packet+pos,tag,TAGSIZE);

    return packet;

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

    int counter2 = 0;

    dir = opendir(path);
    if (!dir)
    {
        throw Exception("Directory not exists\n");
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
            counter2++;
        }
    }
    if (counter2 == 0)
    {
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
    char* filePath = &file_path[0];
    
    int ret = remove(filePath);
    uint32_t siz;
    free(this->file_name);
    if (ret != 0)
    {
        cerr << "DELETE - ERROR\n";
        char msg[] = "DELETE - ERROR\n";
        unsigned char *pac;
        if (this->counter == UINT16_MAX)
    		throw ExitException("Counter exceeded\n");
        this->counter++;
        pac = prepare_msg_packet(&siz, msg, sizeof(msg), ACK, counter, this->shared_key);        
        cm.send_packet(pac, siz);
        printf("Packet sent\n");
    }
    else{
        printf("DELETE - OK\n");
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

//Deserializes a rename packet and rename
//the file, if it exists

void server::server_hello(unsigned char* nonce) {

    uint8_t opcode=SHELLO_OPCODE;
    crypto *c=new crypto();
    this->snonce=(unsigned char*)malloc(NONCESIZE);//TEST
    c->create_nonce(snonce);

    string cacert_file_name = "./server_file/server/Server_cert.pem";

    // open the file to sign:
    FILE *cacert_file = fopen(cacert_file_name.c_str(), "r");
    if(!cacert_file) { throw Exception("Cannot open CA cert file\n");; }

    // get the file size:
    // (assuming no failures in fseek() and ftell())
    fseek(cacert_file, 0, SEEK_END);
    long int clear_size = ftell(cacert_file);
    fseek(cacert_file, 0, SEEK_SET);

    // read the plaintext from file:
    unsigned char* cert = (unsigned char*)malloc(clear_size);
    if(!cert) { throw Exception("Malloc returned null\n"); }
    int ret = fread(cert, 1, clear_size, cacert_file);
    if(ret < clear_size) { throw Exception("Error while reading file\n"); }
    fclose(cacert_file);

    uint32_t cert_size=(uint32_t)clear_size;

    this->my_prvkey= c->dh_keygen();
 
    uint32_t key_siz;

    BIO* bio=BIO_new(BIO_s_mem());
    ret= PEM_write_bio_PUBKEY(bio, my_prvkey);
    if (ret == 0) {
        throw Exception("Error in PEM_write_bio_PUBKEY\n");
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    char* key = (char*)malloc(bptr->length);
    memcpy(key,bptr->data,bptr->length);
    BIO_free(bio);
    key_siz=bptr->length;

    int sign_size=key_siz+sizeof(nonce);
    unsigned char* tosign=(unsigned char*)malloc(sign_size);
    int pos=0;
    memcpy(tosign,key,key_siz);
    pos+=key_siz;

    uint16_t  nonce_size=sizeof(nonce);
    memcpy(tosign+pos,nonce,nonce_size);

    unsigned int sgnt_size;
    unsigned char* sign=c->signn(tosign,sign_size,"./server_file/server/Server_key.pem",&sgnt_size);
    uint32_t pkt_len=sizeof(opcode)+sizeof(uint16_t)+sizeof(uint32_t)*3+nonce_size+key_siz+cert_size+(sgnt_size);
    unsigned char* pkt = (unsigned char*)malloc(pkt_len);

    pos=0;
    memcpy(pkt,&opcode,sizeof(opcode));
    pos+=sizeof(opcode);

    uint16_t nonce_size_s=htons(nonce_size);
    memcpy(pkt+pos,&nonce_size_s,sizeof(uint16_t));
    pos+=sizeof(uint16_t);

    uint32_t cert_size_s=htonl(cert_size);
    memcpy(pkt+pos,&cert_size_s,sizeof(uint32_t));
    pos+=sizeof(uint32_t);

    uint32_t key_size_s=htonl(key_siz);
    memcpy(pkt+pos,&key_size_s,sizeof(uint32_t));
    pos+=sizeof(uint32_t);

    uint32_t sgnt_size_s=htonl(sgnt_size);
    memcpy(pkt+pos,&sgnt_size_s,sizeof(uint32_t));
    pos+=sizeof(uint32_t);

    memcpy(pkt+pos,snonce,nonce_size);
    pos+=nonce_size;

    memcpy(pkt+pos,cert,cert_size);
    pos+=cert_size;

    memcpy(pkt+pos,key,key_siz);
    pos+=key_siz;

    memcpy(pkt+pos,sign,ntohl(sgnt_size_s));
    cm.send_packet(pkt,pkt_len);
    free(tosign);
    free(sign);
    free(key);

}

void server::auth(unsigned char* pkt, int pos) {

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
        throw Exception("Error in Bio_write\n");;
    }

    EVP_PKEY* pubkey=PEM_read_bio_PUBKEY( bio, NULL, NULL, NULL);
    if(pubkey==NULL){
        throw Exception("Error in PEM_read_bio_PUBKEY\n");
    }

    unsigned char* to_verify = (unsigned char*)malloc(key_siz+8);
    pos=0;
    memcpy(to_verify+pos,key,key_siz);

    pos+=key_siz;
    memcpy(to_verify+pos,this->snonce,NONCESIZE);

    string newnamepath = "server_file/client/"; //    ../server_file/client/
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
        throw Exception("Signature not valid\n");
    }
    EVP_PKEY_free(user_pk);
    unsigned char* g=c->dh_sharedkey(this->my_prvkey,pubkey,&this->key_size);
    this->shared_key=c->key_derivation(g,this->key_size);
    uint32_t pkt_len;
    char msg[]="Connection established";
    if (this->counter == UINT16_MAX)
    	throw ExitException("Counter exceeded\n");
    this->counter++;
    unsigned char* packet= prepare_msg_packet(&pkt_len,msg,sizeof(msg),ACK,counter,this->shared_key);
    cm.send_packet(packet,pkt_len);
    fclose(file);
    BIO_free(bio);
    EVP_PKEY_free(pubkey);
    free(key);
    free(sign);
    free(to_verify);
}

//~Andrea

//Deserializes a rename packet and rename
//the file, if it exists

bool server::rename_file(unsigned char* pkt, int pos) {

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
        cerr << "counter errato";
    }

    memcpy(&old_size, pkt + pos, sizeof(old_size)); // Old_size
    pos += sizeof(old_size);
    old_size = ntohs(old_size);
    int old_sizer = old_size+1;
    char* filename = (char*)malloc(old_sizer);

    memcpy(&new_size, pkt + pos, sizeof(new_size)); // New_size
    pos += sizeof(new_size);
    new_size = ntohs(new_size);
    int new_sizer = new_size + 1;
    char* newfilename = (char*)malloc(new_sizer);

    memcpy(&cipher_size, pkt + pos, sizeof(cipher_size)); // Cipher_size
    pos += sizeof(cipher_size);
    cipher_size = ntohl(cipher_size);
    unsigned char* ct = (unsigned char*)malloc(cipher_size);

    crypto c = crypto(); // IV
    unsigned char iv[IVSIZE];
    memcpy(iv, pkt + pos, IVSIZE);
    pos += IVSIZE;

    memcpy(ct, pkt + pos, cipher_size); //CT & TAG
    pos += cipher_size;
    unsigned char tag[TAGSIZE];
    memcpy(tag, pkt + pos, TAGSIZE);
    int aad_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
    unsigned char* pt = (unsigned char*)malloc(cipher_size);
    unsigned char* aad = (unsigned char*)malloc(aad_size);
    memcpy(aad, pkt, aad_size);
    c.decrypt_message(ct, cipher_size, aad, aad_size, tag, this->shared_key, iv, pt);

    string temp = (char*)pt;
    string old = temp.substr(0, old_size);
    string news = temp.substr(old_size, new_size);

    strcpy(filename ,old.c_str()); // Old name
    strcpy(newfilename, news.c_str()); // New name

    // End Deserialization

    if (nameChecker(filename, FILENAME)) //Check if username format is correct
    {
        if (file_opener(filename, logged_user)) //Check if the file exists
        {
            bool b = file_renamer(newfilename, filename);
            if(b)
            {
                printf("Rename - OK\n");
                free(ct);
                free(newfilename);
                free(filename);
                free(aad);
                free(pt);
                return true;
            }

            else
            {
                printf("Rename - Error\n");
                free(ct);
                free(newfilename);
                free(filename);
                free(aad);
                free(pt);
                return false;
            }

        }
        else 
        {
            printf("file %s - Not Found.\n", filename);
            /*unsigned char* packet;
            uint8_t code = RENAME_NACK;
            memcpy(packet, &code, sizeof(code));
            cm.send_packet(packet, sizeof(code));*/
            free(ct);
            free(newfilename);
            free(filename);
            free(aad);
            free(pt);
            return false;
        }
    } 
    else 
    {
        printf("filename %s - Error. Format not valid\n", filename);
        /*unsigned char *packet;
        uint8_t code = RENAME_NACK;
        memcpy(packet, &code, sizeof(code));
        cm.send_packet(packet, sizeof(code));*/
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

bool server::file_renamer(char* new_name, char* old_name){

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
	
	if (rename(old_name, new_name) != 0)
    {
        return false;
    }
	else
    {
        return true;
    }
		
}
