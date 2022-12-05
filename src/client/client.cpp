#include "client.h"

Client::Client(string username, string srv_ip) {
    this->username = username;
    active_session = new Session();

    if(!createSocket(srv_ip)) {
        perror("Socket creation error");
        exit(1);
    };
}

Client::~Client() {
    //TODO: check if everything is deallocated
    active_session = nullptr;
    username.clear();
    if(!send_buffer.empty()) {
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
    }
    if(!recv_buffer.empty()) {
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();
    }
}

bool Client::createSocket(string srv_ip) {
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {  // socket TCP
        return false;
    }
    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = htons(SRV_PORT);
    if(inet_pton(AF_INET, srv_ip.c_str(), &sv_addr.sin_addr) != 1) {
        cerr << "Server IP not valid" << endl;
        return false;
    }
    if(connect(sd, (struct sockaddr*)&sv_addr, sizeof(sv_addr)) != 0) {
        cerr << "Connection to server failed" << endl;
        return false;
    }
    
    return true;
}

/********************************************************************/
// send/receive

/**
 * send a message to the server
 * @payload_size: body lenght of the message to send
 * @return: 1 on success, 0 or -1 on error
 */
int Client::sendMsg(uint32_t payload_size) {
    cout << "sendMsg new" << endl;
    if(payload_size > MAX_BUF_SIZE - NUMERIC_FIELD_SIZE) {
        cerr << "Message to send too big" << endl;
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
        return -1;
    }
    payload_size += NUMERIC_FIELD_SIZE;
    cout << "sentMsg->payload size: " << payload_size << endl;
    if(send(sd, send_buffer.data(), payload_size, 0) < payload_size) {
        perror("Socker error: send message failed");
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
        return -1;
    }
    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();

    return 1;    
 }

/**
 * receive message from server
 * @return: return the payload length of the received message, or 0 or -1 on error
*/
 long Client::receiveMsg() {
    cout << "receiveMsg new" << endl;

    array<unsigned char, MAX_BUF_SIZE> receiver;
    ssize_t msg_size = 0;
    uint32_t payload_size;

    recv_buffer.assign(recv_buffer.size(), '0');
    recv_buffer.clear();

    msg_size = recv(sd, receiver.data(), MAX_BUF_SIZE-1, 0);
    cout << "received msg size: " << msg_size << endl;

    if (msg_size == 0) {
        cerr << "The connection has been closed" << endl;
        return 0;
    }

    if (msg_size < 0 || msg_size < (uint)NUMERIC_FIELD_SIZE + (uint)OPCODE_SIZE) {
        perror("Socket error: receive message failed");
        receiver.fill('0');
        return -1;
    }

    payload_size = *(uint32_t*)(receiver.data());
    payload_size = ntohl(payload_size);
    cout << payload_size << " received payload length" << endl;
    //check if all data are received
    if (payload_size != msg_size - (int)NUMERIC_FIELD_SIZE) {
        cerr << "Error: Data received too short (malformed message?)" << endl;
        receiver.fill('0');
        return -1;
    }

    recv_buffer.insert(recv_buffer.begin(), receiver.begin(), receiver.begin() + msg_size);
    receiver.fill('0');     // clear content of the temporary receiver buffer

    return payload_size;

 }

/********************************************************************/


bool Client::authentication() {
    cout << "Client->autentication\n";
    
    int ret;
    array<unsigned char, NONCE_SIZE> client_nonce;
    vector<unsigned char> server_nonce;

    EVP_PKEY *my_priv_key;

    // M1
    if(sendUsername(client_nonce) != 1) {
        cerr << "Authentication->sendUsername failed" << endl;
        return false;
    }
    

    // M2: receive server cert e ECDH_server_key
    cout << "authentication->receiveMsg" << endl;

    // receive M2
    if(!receiveCertSign(client_nonce, server_nonce)) {
        cerr << "Authentication->receiveCertSign failed" << endl;
        return false;
    }
    
    my_priv_key = active_session->retrievePrivKey("./client/users/" + username + "/" + username + "_key.pem");
    active_session->generateECDHKey();
    ret = sendSign(server_nonce, my_priv_key);
    cout << "sendsign serv nonce" << endl;
    server_nonce.clear();
    if(ret != 1) {
        cerr << "sendSign failed " << endl;
        EVP_PKEY_free(my_priv_key);
        return false;
    }

    active_session->deriveSecret();     // derive secrete & compute session key
    cout << "active_session -> derive secret " << endl;
    // TODO
    //receive login ack or file list?
    //receiveFileList();
    return true;
}

/********************************************************************/

// Message M1
int Client::sendUsername(array<unsigned char, NONCE_SIZE> &client_nonce) {
    cout << "sendUsername\n";
    uint start_index = 0;
    uint32_t payload_size = OPCODE_SIZE + NONCE_SIZE + username.size();
    uint32_t payload_n = htonl(payload_size);
    uint16_t opcode;

    if(active_session->generateNonce(client_nonce.data()) != 1) {
        cerr << "generateNonce failed" << endl;
        return -1;
    }

    // clear content of the sender buffer
    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();    //fill('0');
    //memset(send_buffer, 0, MAX_BUF_SIZE);

    // prepare buffer: | payload_size | opcode_LOGIN | nonce_client | username |
    //memcpy(vec.data(), &p, NUMERIC_FIELD_SIZE);
    send_buffer.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    memcpy(send_buffer.data(), &payload_n, NUMERIC_FIELD_SIZE);
    start_index += NUMERIC_FIELD_SIZE;

    opcode = htons((uint16_t)LOGIN);
    memcpy(send_buffer.data() + NUMERIC_FIELD_SIZE, &opcode, OPCODE_SIZE);
    start_index += OPCODE_SIZE;

    send_buffer.insert(send_buffer.end(), client_nonce.begin(), client_nonce.end());
    //memcpy(send_buffer.data() + start_index, active_session->nonce.data(), NONCE_SIZE);
    start_index += NONCE_SIZE;

    send_buffer.insert(send_buffer.end(), username.begin(), username.end());
    //memcpy(send_buffer.data() + start_index, username.c_str(), username.size());
    start_index += username.size();

    //cout << "sendUsername buffer msg: " << endl;
    //BIO_dump_fp(stdout, (const char*)send_buffer.data(), send_buffer.size());

    //sendMsg
    cout << "authentication->sendMsg M1: nonce, username " << endl;
    if(sendMsg(payload_size) != 1) {
        client_nonce.fill('0');
        return -1;
    }
    return 1;
}

// M2
bool Client::receiveCertSign(array<unsigned char, NONCE_SIZE> &client_nonce, 
                            vector<unsigned char> &srv_nonce) {
    cout << "receiveCertSign\n";

    long payload_size;
    uint start_index = 0;
    uint16_t opcode;
    
    vector<unsigned char> received_nonce;
    vector<unsigned char> temp_buffer;

    uint32_t cert_size;
    EVP_PKEY* srv_pubK;
    uint32_t ECDH_key_size;
    vector<unsigned char> ECDH_server_key;
    long dig_sign_len;
    vector<unsigned char> server_signature;
    uint32_t signed_msg_len;

    payload_size =  receiveMsg();
    if(payload_size <= 0) {
        cerr << "Error on the receiveMsg -> closing connection..." << endl;
        return false;
    }
    
    //cout << "receiveCertSign buffer msg: " << endl;
    //BIO_dump_fp(stdout, (const char*)recv_buffer.data(), recv_buffer.size());

    start_index = NUMERIC_FIELD_SIZE;   // reading starts after payload_size field

    // check opcode
    opcode = *(uint16_t*)(recv_buffer.data() + start_index);
    opcode = ntohs(opcode);
    start_index += OPCODE_SIZE;
    //cout << "start index " << start_index << endl;
    if(opcode != LOGIN) {
        if(opcode == ERROR) {
            string errorMsg(recv_buffer.begin() + start_index, recv_buffer.end());
            cerr << errorMsg << endl;
        } else {
            cerr << "Received not expected message" << endl;
        }
        
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();

        return false;
    }

    if(start_index >= recv_buffer.size() - (uint)NONCE_SIZE - (uint)NONCE_SIZE) {
        cerr << "Received msg size error" << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();
        return false;
    }

    // retrieve & check client nonce
    received_nonce.insert(received_nonce.begin(), 
                        recv_buffer.begin() + start_index, 
                        recv_buffer.begin() + start_index + NONCE_SIZE);
    //memcpy(received_nonce.data(), recv_buffer.data() + start_index, NONCE_SIZE);
    start_index += NONCE_SIZE;

    
    if(!active_session->checkNonce(received_nonce.data(), client_nonce.data())) {
        cerr << "Received nonce not valid\n";

        received_nonce.clear();
        client_nonce.fill('0');
        // TODO: check and clear all used buffers
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();    //fill('0');

        return false;
    }
    cout << "Received nonce verified!" << endl;

    // retrieve server nonce
    srv_nonce.insert(srv_nonce.begin(), 
                    recv_buffer.begin() + start_index, 
                    recv_buffer.begin() + start_index + NONCE_SIZE);
    //memcpy(srv_nonce.data(), recv_buffer.data() + start_index, NONCE_SIZE);   // server nonce
    start_index += NONCE_SIZE;

    if(start_index >= recv_buffer.size() - (uint)NUMERIC_FIELD_SIZE) {
        cerr << "Received msg size error " << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();
        return false;
    }

    // retrieve server cert
    cert_size = *(uint32_t*)(recv_buffer.data() + start_index);
    cert_size = ntohl(cert_size);
    start_index += NUMERIC_FIELD_SIZE;
    
    if(start_index >= recv_buffer.size() - cert_size) {
        cerr << "Received msg size error " << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();
        return false;
    }

    // get server certificate
    temp_buffer.insert(temp_buffer.begin(), 
                recv_buffer.begin() + start_index, 
                recv_buffer.begin() + start_index + cert_size);
    
    start_index += cert_size;

    // deserialize, verify certificate & extract server pubKey
    if(!verifyCert(temp_buffer.data(), cert_size, srv_pubK)) {
        cerr << "Server certificate not verified\n";

        temp_buffer.assign(temp_buffer.size(), '0');
        recv_buffer.assign(recv_buffer.size(), '0');

        temp_buffer.clear();
        recv_buffer.clear();

        return false;
    }
    cout << "Server certificate verified!" << endl;
    //memset(buffer.data(), '0', buffer.size());
    temp_buffer.assign(temp_buffer.size(), '0');
    temp_buffer.clear();
    
    if(start_index >= recv_buffer.size() - (uint)NUMERIC_FIELD_SIZE) {
        cerr << "Received msg size error " << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();
        return false;
    }

    // retrieve ECDH server pub key: size + key
    ECDH_key_size = *(uint32_t*)(recv_buffer.data() + start_index);
    ECDH_key_size = ntohl(ECDH_key_size);
    start_index += NUMERIC_FIELD_SIZE;
    
    if(start_index >= recv_buffer.size() - ECDH_key_size) {
        cerr << "Received msg size error " << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();
        return false;
    }

    //get key
    ECDH_server_key.insert(ECDH_server_key.begin(), 
                        recv_buffer.begin() + start_index,
                        recv_buffer.begin() + start_index + ECDH_key_size);

    start_index += ECDH_key_size;

    // retrieve digital signature
    dig_sign_len = recv_buffer.size() - start_index;
    if(dig_sign_len <= 0) {
        cerr << "Dig_sign length error " << endl;
        ECDH_server_key.assign(ECDH_server_key.size(), '0');
        ECDH_server_key.clear();
        return false;
    }

    server_signature.insert(server_signature.begin(), 
                        recv_buffer.begin() + start_index, 
                        recv_buffer.end());
    start_index += dig_sign_len;
    if(start_index - NUMERIC_FIELD_SIZE != payload_size) {
        cerr << "Received data size error" << endl;
        server_signature.assign(server_signature.size(), '0');
        ECDH_server_key.assign(ECDH_server_key.size(), '0');
        ECDH_server_key.clear();
        server_signature.clear();
        return false;
    }
    
    // verify digital signature
    signed_msg_len = NONCE_SIZE + ECDH_key_size;

    // nonce client
    if(!temp_buffer.empty()) {
        temp_buffer.assign(temp_buffer.size(), '0');
        temp_buffer.clear();
    }
    temp_buffer.insert(temp_buffer.begin(), client_nonce.begin(), client_nonce.end());
    //memcpy(temp_buffer.data(), client_nonce.data(), NONCE_SIZE);
    start_index = NONCE_SIZE;
    // server ECDH public key
    temp_buffer.insert(temp_buffer.end(), ECDH_server_key.begin(), ECDH_server_key.end());
    //memcpy(temp_buffer.data() + start_index, ECDH_server_key.data(), ECDH_key_size);
    bool verified = active_session->verifyDigSign(server_signature.data(), dig_sign_len, 
                                                    srv_pubK, temp_buffer.data(), signed_msg_len);
    
    // clear buffer
    //memset(buffer.data(), '0', buffer.size());
    //memset(server_dig_sign.data(), '0', server_dig_sign.size());
    temp_buffer.assign(temp_buffer.size(), '0');
    server_signature.assign(server_signature.size(), '0');

    temp_buffer.clear();
    server_signature.clear();

    if(!verified) {
        cerr << "Digital Signature not verified" << endl;

        // clear buffer key
        ECDH_server_key.assign(ECDH_server_key.size(), '0');
        //memset(ECDH_server_key.data(), '0', ECDH_server_key.size());
        ECDH_server_key.clear();

        return false;
    }
    cout << " Digital Signature Verified!" << endl;
    //free(signed_msg);
    //BIO_dump_fp(stdout, (const char*) ECDH_server_key.data(), ECDH_key_size);
    active_session->deserializePubKey(ECDH_server_key.data(), ECDH_key_size, active_session->ECDH_peerKey);
    return true;
}

/**
 * send client digital signature
 * @srv_nonce: vector containing the nonce sent by the server, to re-send to the server
 * @priv_k: client private key needed to sign the message
 * @return: 1 on success, 0 or -1 on error (return of sendMsg())
*/
int Client::sendSign(vector<unsigned char> &srv_nonce, EVP_PKEY *&priv_k) {
    cout << "Client -> sendSign " << endl;

    int ret = 0;

    unsigned char* ECDH_my_pub_key = nullptr;
    uint32_t ECDH_my_key_size;
    uint32_t ECDH_my_key_size_n;
    
    vector<unsigned char> msg_to_sign;
    vector<unsigned char> signed_msg(EVP_PKEY_size(priv_k));
    long signed_msg_len;

    uint32_t payload_size;
    uint32_t payload_n;
    uint16_t opcode;
    uint32_t start_index;

    ECDH_my_key_size = active_session->serializePubKey(
                                    active_session->ECDH_myKey, ECDH_my_pub_key);


    cout << "ECDH_my_key_size " << ECDH_my_key_size << endl;
    msg_to_sign.resize(ECDH_my_key_size);
    msg_to_sign.insert(msg_to_sign.begin(), srv_nonce.begin(), srv_nonce.end());
    //memcpy(msg_to_sign, srv_nonce.data(), NONCE_SIZE);
    memcpy(msg_to_sign.data() + NONCE_SIZE, ECDH_my_pub_key, ECDH_my_key_size);
    
    signed_msg_len = active_session->signMsg(msg_to_sign.data(), NONCE_SIZE + ECDH_my_key_size, priv_k, signed_msg.data());

    if( signed_msg_len < 0) {
        cerr << "signMsg failed" << endl;
        msg_to_sign.assign(msg_to_sign.size(), '0');
        msg_to_sign.clear();
        return -1;
    }
    //cout << "client: singMsg done" << endl;    

    // prepare send buffer
    if(!send_buffer.empty()) {
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
    }
    send_buffer.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE + NUMERIC_FIELD_SIZE + ECDH_my_key_size);
    //memset(send_buffer, 0, MAX_BUF_SIZE);

    payload_size = OPCODE_SIZE + NONCE_SIZE + NUMERIC_FIELD_SIZE + ECDH_my_key_size + signed_msg_len;
    payload_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_n, NUMERIC_FIELD_SIZE);
    start_index = NUMERIC_FIELD_SIZE;

    opcode = htons((uint16_t)LOGIN);
    memcpy(send_buffer.data() + start_index, &opcode, OPCODE_SIZE);
    start_index += OPCODE_SIZE;

    send_buffer.insert(send_buffer.begin() + start_index, srv_nonce.begin(), srv_nonce.end());
    cout << "serv_nonce inserted" << endl;
    //memcpy(send_buffer.data() + start_index, srv_nonce.data(), NONCE_SIZE);
    start_index += NONCE_SIZE;

    ECDH_my_key_size_n = htonl(ECDH_my_key_size);
    memcpy(send_buffer.data() + start_index, &ECDH_my_key_size_n, NUMERIC_FIELD_SIZE);  
    cout << "memcpy ecdh_key_size done" << endl;  
    start_index += NUMERIC_FIELD_SIZE;

    memcpy(send_buffer.data() + start_index, ECDH_my_pub_key, ECDH_my_key_size);
    cout << "memcpy ecdh_pub_key done" << endl;
    start_index += ECDH_my_key_size;
    cout << "start index after ecdh key " << start_index << endl; 
    
    send_buffer.insert(send_buffer.end(), signed_msg.begin(), signed_msg.end());
    cout << "signed msg inserted " << endl;
    //memcpy(send_buffer.data() + start_index, signed_msg, signed_msg_len);

    // send msg to server
    cout <<"authentication sendMsg (ecdh pub key)" << endl;
    ret = sendMsg(payload_size);

    // clear buffer
    //memset(msg_to_sign.data(), '0', msg_to_sign.size());
    //memset(signed_msg.data(), '0', signed_msg.size());
    msg_to_sign.assign(msg_to_sign.size(), '0');
    signed_msg.assign(signed_msg.size(), '0');

    msg_to_sign.clear();
    signed_msg.clear();

    cout << "sendSign end" << endl;

    return ret;
}


/********************************************************************/

bool Client::buildStore(X509*& ca_cert, X509_CRL*& crl, X509_STORE*& store) {
    // load CA certificate
    string ca_cert_filename = "./client/FoundationOfCybersecurity_cert.pem";    // controllare percorso directory
    FILE* ca_cert_file = fopen(ca_cert_filename.c_str(), "r");
    if(!ca_cert_file) {
        cerr << "CA_cert file does not exists" << endl;
        return false;
    }
    
    ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);

    if(!ca_cert){
       cerr << "PEM_read_X509 returned NULL" << endl;
       return false;
    }
    // load the CRL
    string crl_filename = "./client/FoundationOfCybersecurity_crl.pem";
    FILE* crl_file = fopen(crl_filename.c_str(), "r");
    if(!crl_file) {
        cerr << "CRL file not found" << endl;
        return false;
    }
    crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);

    if(!crl){
        cerr << "PEM_read_X509_CRL returned NULL " << endl;
        return false;
    }
    // build a store with CA_cert and the CRL
    store = X509_STORE_new();
    if(!store) {
        cerr << "X509_STORE_new returned NULL\n" 
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        return false;
    }
    if(X509_STORE_add_cert(store, ca_cert) != 1) {
        cerr << "X509_STORE_add_cert error\n"
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        return false;
    }
    if(X509_STORE_add_crl(store, crl) != 1) {
        cerr << "X509_STORE_add_crl error\n" 
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        return false;
    }
    if(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1) {
        cerr << "X509_STORE_set_flags error\n" 
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        return false;
    }

    return true;
}

bool Client::verifyCert(unsigned char* cert_buf, long cert_size, EVP_PKEY*& srv_pubK) {

    bool verified = false;

    X509* CA_cert = nullptr;
    X509_CRL * CA_crl = nullptr;
    X509_STORE* store = nullptr;
    X509_STORE_CTX* certvfy_ctx = nullptr;

    X509* certToCheck = d2i_X509(NULL, (const unsigned char**)&cert_buf, cert_size);
    if(!certToCheck) {
        cerr << "d2i_X509 failed" << endl;
        return false;
    }

    if(!buildStore(CA_cert, CA_crl, store)) {
        cerr << "buildStore failed" << endl;

        X509_free(certToCheck);

        X509_free(CA_cert);
        X509_CRL_free(CA_crl);
        X509_STORE_free(store); // deallocates also CA_cert and CRL
    }


    // verify peer's certificate
    certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) {
        cerr << "X509_STORE_CTX_new returned NULL\n"
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        X509_free(certToCheck);

        X509_free(CA_cert);
        X509_CRL_free(CA_crl);
        X509_STORE_free(store);
        
        X509_STORE_CTX_free(certvfy_ctx);

        return false;
    }
    if(X509_STORE_CTX_init(certvfy_ctx, store, certToCheck, NULL) != 1) {
        cerr << "X50_STORE_CTX_init error\n" 
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        
        X509_free(certToCheck);

        X509_free(CA_cert);
        X509_CRL_free(CA_crl);
        X509_STORE_free(store);
        
        X509_STORE_CTX_free(certvfy_ctx);

        return false;
    }
    verified = X509_verify_cert(certvfy_ctx) == 1;

    if(verified) {        
        srv_pubK = X509_get_pubkey(certToCheck);    // extract server public key from certificate
        // print the successful verification to screen
            //oneline -> distinguished name
        char *tmp = X509_NAME_oneline(X509_get_subject_name(certToCheck), NULL, 0);
        char *tmp2 = X509_NAME_oneline(X509_get_issuer_name(certToCheck), NULL, 0);
        cout << "Certificate of '" << tmp << "' (released by '" << tmp2 << "') verified successfully\n";
        free(tmp);
        free(tmp2);
    }

    X509_free(certToCheck);
    X509_STORE_free(store); // deallocates also CA_cert and CRL
    X509_STORE_CTX_free(certvfy_ctx);

    return verified;
}

void Client::showCommands() {
    cout << "\n-----------------------------------------------\n";
    cout << "Commands menu" << endl;
    cout << "!help -> show this commands list" << endl;
    cout << "!list -> show list of available files" << endl;
    cout << "!upload -> upload an existing file in your cloud storage" << endl;
    cout << "!download -> download a file from your cloud storage" << endl;
    cout << "!rename -> rename a file in your cloud storage" << endl;
    cout << "!delete -> delete a file from your cloud storage" << endl;
    cout << "!exit -> logout from server and exit program" << endl;

}

// TODO
bool Client::handlerCommand(string& command) {
    cout << "client->hanlerCommand\n";
    //if else con la gestione dei diversi comandi, es. se rtt => readInput per leggere l'username con cui si vuole chattare (lato server va controllato che il nome sia corretto)
    if(command.compare("!help") == 0)
        showCommands();
    else if(command.compare("!list") == 0) {
        // opcode 8
        cout << "FileList operation requested" << endl;
        requestFileList();
        /*
        string msg = "Available users?";
        active_session->userList((unsigned char*)msg.c_str(), msg.length());*/
        // se unsigned char msg[] => active_session->userList(msg, sizeof(msg));
    } else if(command.compare("!upload") == 0) {
        // opcode 1
        cout << "Upload operation requested" << endl;
        // TODO
        uploadFile();    // username saved in class member
    } else if(command.compare("!download") == 0) {
        // opcode 2
        cout << "Download operation requested" << endl;
        // TODO
        downloadFile();
    } else if(command.compare("!rename") == 0) {
        // opcode 3
        cout << "Rename operation requested " << endl;
        // TODO
        renameFile();    // username saved in class member
    } else if(command.compare("!delete") == 0) {
        // opcode 4
        cout << "Delete operation requested" << endl;
        // TODO
        deleteFile();
    } else if(command.compare("!exit") == 0) {
        // logout from server - opcode 10
        cout << "Logout requested" << endl; 
        // TODO
        logout();        
    } else {
        cout << "Invalid command" << endl;
        return false;
    }
    return true;
}

int Client::requestFileList() {
    string msg = this->username;
    uint32_t payload_size, payload_size_n;
    vector<unsigned char> aad(AAD_LEN);
    vector<unsigned char> plaintext;
    array<unsigned char, MAX_BUF_SIZE> output;

    cout<<"****************************************"<<endl;
    cout<<"******     Request File List      ******"<<endl;
    cout<<"****************************************"<<endl;


    plaintext.insert(plaintext.begin(), msg.begin(), msg.end());

    this->active_session->createAAD(aad.data(), FILE_LIST);
    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    payload_size_n = htonl(payload_size);
        
    clear_three_vec(aad, plaintext, send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    output.fill('0');

    if(sendMsg(payload_size) != 1){
        cerr<<"Error during send phase (C->S | File List Request)"<<endl;
        return -1;
    }

    int ret = receiveFileList();

    cout<<"****************************************"<<endl;
    cout<<"*****     File List Received       *****"<<endl;
    cout<<"****************************************"<<endl;

    
    if(ret == -1)
        return -1;
    else
        return 1;
}

int Client::receiveFileList() {
    vector<unsigned char> aad(AAD_LEN);
    vector<unsigned char> plaintext(MAX_BUF_SIZE);
    int received_len, pt_len;
    uint16_t opcode;
    string filelist = "";

    while(true){
        received_len = receiveMsg();
        if(received_len == -1 || received_len == 0){
            cerr<<"Error! Exiting receive file list phase"<<endl;
            return -1;
        }
        pt_len = this->active_session->decryptMsg(recv_buffer.data(), recv_buffer.size(), aad.data(), plaintext.data());

        opcode = ntohs(*(uint16_t*)(aad.data()+NUMERIC_FIELD_SIZE));

        //TODO if the list of file exceed the space available in a single message

        if(opcode == FILE_LIST)
            cout<<((char*)plaintext.data());
        else if(opcode == END_OP){
            cout<<((char*)plaintext.data());
            break;
        }
        else{
            cerr<<"Error! The received msg was malformed"<<endl;
            return -1;
        }

        clear_two_vec(plaintext, aad);
    }
    return 0;
}

void Client::logout() {
    vector<unsigned char> aad(AAD_LEN);
    vector<unsigned char> plaintext(FILE_SIZE_FIELD);
    array<unsigned char, MAX_BUF_SIZE> output;
    uint32_t payload_size, payload_size_n;
    string msg = "Close this client session";

    plaintext.insert(plaintext.begin(), msg.begin(), msg.end());
    this->active_session->createAAD(aad.data(), LOGOUT);

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    payload_size_n = htonl(payload_size);

    clear_three_vec(aad, plaintext, send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    while(sendMsg(payload_size) != 1)
        cerr<<"Error during logout phase! Trying again"<<endl;

    this->active_session->~Session();
    this->~Client();
}
    

void Client::sendErrorMsg(string errorMsg) {
        //cerr << errorMsg << endl;

        // inviare mess errore al client
        int payload_size = OPCODE_SIZE + errorMsg.size();
        uint16_t op = ERROR;

        int written = 0;
        send_buffer.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
        memcpy(send_buffer.data(), &payload_size, NUMERIC_FIELD_SIZE);
        written += NUMERIC_FIELD_SIZE;
        memcpy(send_buffer.data() + written, &op, OPCODE_SIZE);
        written += OPCODE_SIZE;
        send_buffer.insert(send_buffer.end(), errorMsg.begin(), errorMsg.end());
        
        sendMsg(payload_size);

}

uint32_t Client::sendMsgChunks(string filename){
    string path = "./users/" + this->username + "/" + filename;                         //where to find the file
    FILE* file = fopen(path.c_str(), "rb");                                             //opened file
    struct stat buf;

    if(!file){
        cerr<<"Error during file opening";
        return -1;
    }

    if(stat(path.c_str(), &buf) != 0){
        cerr<<filename + "doesn't exist in " + this->username + "folder" <<endl;
        return -1;
    }

    size_t tot_chunks = ceil((float)buf.st_size / FRAGM_SIZE);                          //total number of chunks needed form the upload
    size_t to_send;                                                                     //number of byte to send in the specific msg
    uint32_t payload_size, payload_size_n;                                              //size of the msg payload both in host and network format
    int ret;                                                                            //bytes read by the fread function
    vector<unsigned char> aad(AAD_LEN);                                                          //aad of the msg
    array<unsigned char, FRAGM_SIZE> frag_buffer;                                       //msg to be encrypted
    array<unsigned char, MAX_BUF_SIZE> output;                                          //encrypted text
    
    clear_vec_array(send_buffer, frag_buffer.data(), frag_buffer.size());
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    for(int i = 0; i < tot_chunks; i++){
        if(i == tot_chunks - 1){
            to_send = buf.st_size - i * FRAGM_SIZE;
            this->active_session->createAAD(aad.data(), END_OP);                        //last chunk -> END_OP opcode sent to server
        }
        else{
            to_send = FRAGM_SIZE;
            this->active_session->createAAD(aad.data(), UPLOAD);                        //intermediate chunks
        }

        ret = fread(frag_buffer.data(), sizeof(char), to_send, file);

        if(ferror(file) != 0 || ret != to_send){
            cerr<<"ERROR while reading file"<<endl;
            return -1;
        }

        payload_size = this->active_session->encryptMsg(frag_buffer.data(), frag_buffer.size(), aad.data(), output.data());
        payload_size_n = htonl(payload_size);

        clear_vec_array(aad, frag_buffer.data(), frag_buffer.size());

        memcpy(&payload_size_n, send_buffer.data(), NUMERIC_FIELD_SIZE);
        send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

        clear_vec_array(send_buffer, output.data(), output.size());
        send_buffer.resize(NUMERIC_FIELD_SIZE);

        if(sendMsg(payload_size) != 1){
            cerr<<"Error during send phase (C->S) | Upload Chunk Phase (chunk num: "<<i<<")"<<endl;
            return -1;
        }
    }
    return 1;
}



int Client::uploadFile(){
    uint64_t file_dim;                                                      //dimension (in byte) of the file to upload
    uint32_t payload_size, payload_size_n;                                  //size of the msg payload both in host and network format
    uint32_t file_dim_l_n, file_dim_h_n;                                    //low and high part of the file_dim variable in network form
    string filename;                                                        //name of the file to upload
    vector<unsigned char> aad(AAD_LEN);                                              //aad of the msg
    vector<unsigned char> plaintext(FILE_SIZE_FIELD);                       //plaintext to be encrypted
    array<unsigned char, MAX_BUF_SIZE> output;                              //encrypted text

    cout<<"****************************************"<<endl;
    cout<<"*********     UPLOAD FILE      *********"<<endl;
    cout<<"****************************************"<<endl<<endl;

    readFilenameInput(filename, "Insert filename: ");
    file_dim = searchFile(filename, this->username);

    if(file_dim < 0 && file_dim != -1){
        cerr << "File is too big! Upload terminated" << endl;
        return -1;
    }
    else if  (file_dim == -1){
        cerr << "File not found! Upload not possible" << endl;
        return -1;
    }                      

    //insert in the plaintext filedimension and filename
    file_dim_h_n = htonl((uint32_t) (file_dim >> 32));
    file_dim_l_n = htonl((uint32_t) (file_dim));
    memcpy(plaintext.data(), &file_dim_l_n, NUMERIC_FIELD_SIZE);
    memcpy(plaintext.data() + NUMERIC_FIELD_SIZE, &file_dim_h_n, NUMERIC_FIELD_SIZE);
    plaintext.insert(plaintext.begin() + FILE_SIZE_FIELD, filename.begin(), filename.end());  

    this->active_session->createAAD(aad.data(), UPLOAD_REQ);                

    //send the basic information of the upload operation
    //to be sent: payload_size | IV | count_cs | opcode | {output}_Kcs | TAG

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    payload_size_n = htonl(payload_size);

    //clear aad, plaintext and send_buffer
    clear_three_vec(aad, plaintext, send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    if(sendMsg(payload_size) != 1){
        cerr<<"Error during send phase (C->S | Upload Request Phase)"<<endl;
        return -1;
    }

    //clear send_buffer and output array
    clear_vec_array(send_buffer, output.data(), output.size());
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    //receive from the server the response to the upload request
    //received_len:  legnht of the message received from the server
    //server_response: message from the server containing the response to the request
    int pt_len;                                                          
    uint16_t opcode;
    uint32_t ret;  
    uint64_t received_len;
    string server_response;

    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len == 0 || received_len == -1){
        cerr<<"Error during receive phase (S->C, upload)"<<endl;
        return -1;
    }

    pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
    
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
    if(opcode != UPLOAD_REQ){
        cerr<<"Error! Exiting upload request phase"<<endl;
        return -1;
    }
    
    server_response = ((char*)plaintext.data());
    if(server_response != MESSAGE_OK){       
        cerr<<"File not accepted. "<<server_response<<endl;
        return -1;
    }
   
    //start of the upload
    cout<<"        -------- UPLOADING --------"<<endl;
    
    //clear aad, plaintext and send_buffer
    clear_three_vec(aad, plaintext, send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    ret = sendMsgChunks(filename);

    if(ret == 1){
        //TODO: receive server response to check if file was saved
        aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
        plaintext.resize(MAX_BUF_SIZE);        
        received_len = receiveMsg();
            if(received_len == 0 || received_len == -1){
        cerr<<"Error during receive phase (S->C)"<<endl;
        return -1;
        }
        
        pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
        opcode = ntohs(*(uint16_t*)(aad.data() + sizeof(uint32_t)));
        if(opcode != END_OP){
            cerr<<"Error! Exiting upload phase." << endl;
            return -1;
        }
        if(server_response != OP_TERMINATED){
            cerr<<"Upload not correcty terminated. "<<server_response<<endl;
            return -1;
        }
    }
    else{
        cerr<<"Error! Exiting upload phase"<<endl;
        return -1;
    }
    cout<<"        ---- UPLOAD TERMINATED ----"<<endl<<endl;
    cout<<"****************************************"<<endl<<endl;

    return 1;
}


void Client::downloadFile(){}

int Client::renameFile(){
    string old_filename, new_filename;
    vector<unsigned char> aad(AAD_LEN);                                              //aad of the msg
    vector<unsigned char> plaintext(NUMERIC_FIELD_SIZE);                       //plaintext to be encrypted
    array<unsigned char, MAX_BUF_SIZE> output;
    uint32_t old_filename_lenght, old_filename_lenght_n;   
    uint32_t payload_size, payload_size_n;

    cout<<"****************************************"<<endl;
    cout<<"*********     Rename File      *********"<<endl;
    cout<<"****************************************"<<endl;

    readFilenameInput(old_filename, "Insert the name of the file to be changed: ");
    readFilenameInput(new_filename, "Insert the new name of the file: ");

    old_filename_lenght = old_filename.length();
    old_filename_lenght_n = htonl(old_filename_lenght);
    memcpy(plaintext.data(), &old_filename_lenght_n, NUMERIC_FIELD_SIZE);
    plaintext.insert(plaintext.begin() + NUMERIC_FIELD_SIZE, old_filename.begin(), old_filename.end());
    plaintext.insert(plaintext.begin() + NUMERIC_FIELD_SIZE + old_filename_lenght, new_filename.begin(), new_filename.end());

    this->active_session->createAAD(aad.data(), RENAME_REQ);

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    payload_size_n = htonl(payload_size);

    //clear aad, plaintext and send_buffer
    clear_three_vec(aad, plaintext, send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    output.fill('0');

    if(sendMsg(payload_size) != 1){
        cerr<<"Error during send phase (C->S | Rename Request Phase)"<<endl;
        return -1;
    }
    //send the information of the rename operation
    //to be sent: <count_cs, opcode=3, {old_filename, new_filename}_Kcs>

    //server response: <count_sc, op_code=9, {ResponseMsg}_Kcs>
    aad.resize(AAD_LEN);
    plaintext.resize(MAX_BUF_SIZE);

    uint16_t opcode;
    uint32_t received_len;
    int pt_len;
    string server_response;

    received_len = receiveMsg();
    if(received_len == 0 || received_len == -1){
        cerr <<"Error during receive phase (S->C, rename)";
        return -1;
    }

    pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
    opcode = ntohs(*(uint16_t*)aad.data() + NUMERIC_FIELD_SIZE);
    if(opcode != END_OP){
        cerr << "Error! Exiting rename request phase"<<endl;
        return -1;
    }

    server_response = ((char*)plaintext.data());
    if(server_response != OP_TERMINATED){
        cerr << "Rename not accepted. "<< server_response <<endl;
        return -1;
    }

    cout<<"****************************************"<<endl;
    cout<<"******     Rename Terminated      ******"<<endl;
    cout<<"****************************************"<<endl;

    return 1;
}

void Client::deleteFile(){}