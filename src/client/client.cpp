#include "client.h"

Client::Client(string username, string srv_ip) {
    this->username = username;
    active_session = new Session();

    if(!createSocket(srv_ip)) {
        handleErrors("Socket creation error");
    };
}

Client::~Client() {
    cout << "~Client" << endl;
    //TODO: check if everything is deallocated
    delete active_session;
    //active_session = nullptr;
    username.clear();
    if(!send_buffer.empty()) {
        clear_vec(send_buffer);
    }
    if(!recv_buffer.empty()) {
        clear_vec(recv_buffer);
    }
    close(sd);
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
    uint32_t payload_size_n;
    ssize_t ret;
    array<unsigned char, NUMERIC_FIELD_SIZE> arr;

    if(payload_size > MAX_BUF_SIZE - NUMERIC_FIELD_SIZE) {
        cerr << "Message to send too big" << endl;
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
        return -1;
    }
    payload_size += NUMERIC_FIELD_SIZE;
    payload_size_n = htonl(payload_size);

    memcpy(arr.data(), &payload_size_n, NUMERIC_FIELD_SIZE);

    ret = send(sd, arr.data(), NUMERIC_FIELD_SIZE, 0);

    if(ret < 0 || (ret >= 0 && size_t(ret) < NUMERIC_FIELD_SIZE)){
        perror("Error sending message size");
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
        return -1;
    }
    clear_arr(arr.data(), arr.size());

    //cout << "sentMsg->payload size: " << payload_size << endl;
    ret = send(sd, send_buffer.data(), payload_size, 0);
    if(ret < 0 || (ret >= 0 && size_t(ret) < payload_size)) {
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
    //cout << "receiveMsg new" << endl;

    array<unsigned char, MAX_BUF_SIZE> receiver;
    ssize_t msg_size = 0;
    uint32_t payload_size;

    clear_vec(recv_buffer);

    msg_size = recv(sd, receiver.data(), NUMERIC_FIELD_SIZE, 0);
    cout << "Msg dimension size: " << msg_size << endl;

    payload_size = *(uint32_t*)(receiver.data());
    payload_size = ntohl(payload_size);
    cout << "Msg dimension data: " << payload_size << endl;
    if(payload_size > size_t(MAX_BUF_SIZE - 1)){
        cerr << "Dimension overflow" << endl;
        return -1;
    }

    msg_size = recv(sd, receiver.data(), payload_size, 0);
    //cout << "received msg size: " << msg_size << endl;

    if (msg_size == 0) {
        cerr << "The connection has been closed" << endl;
        return 0;
    }

    if (msg_size < 0 || 
        (msg_size >= 0 && size_t(msg_size) < size_t(NUMERIC_FIELD_SIZE + OPCODE_SIZE))) {
        perror("Socket error: receive message failed");
        receiver.fill('0');
        return -1;
    }

    /*    
    cout << "enc_text: " << endl;
    BIO_dump_fp(stdout, recv_buffer.data(), recv_buffer.size());
    */
    payload_size = *(uint32_t*)(receiver.data());
    payload_size = ntohl(payload_size);
    cout << payload_size << " received payload length" << endl;
    cout << msg_size << " received msg size" << endl;
    //check if all data are received
    if (payload_size != size_t(msg_size) - NUMERIC_FIELD_SIZE) {
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
        //close(sd);
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
    if (my_priv_key == nullptr) {
        cerr << "retrievePrivKey failed" << endl;
        return false;
    }
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

    return receiveFileList() != -1;
    //return true;
}

/********************************************************************/

// Message M1
int Client::sendUsername(array<unsigned char, NONCE_SIZE> &client_nonce) {
    cout << "sendUsername\n";
    uint32_t start_index = 0;
    uint32_t payload_size, payload_n;
    uint16_t opcode;

    if(active_session->generateNonce(client_nonce.data()) != 1) {
        cerr << "generateNonce failed" << endl;
        return -1;
    }

    if (username.size() > UINT32_MAX - OPCODE_SIZE - NONCE_SIZE) {
        cerr << "sendUSername -> size overflow " << endl;
        return -1;
    }
    payload_size = OPCODE_SIZE + NONCE_SIZE + username.size();
    payload_n = htonl(payload_size);

    // clear content of the sender buffer
    clear_vec(send_buffer);

    // prepare buffer: | payload_size | opcode_LOGIN | nonce_client | username |
    send_buffer.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    memcpy(send_buffer.data(), &payload_n, NUMERIC_FIELD_SIZE);
    start_index += NUMERIC_FIELD_SIZE;

    opcode = htons((uint16_t)LOGIN);
    memcpy(send_buffer.data() + NUMERIC_FIELD_SIZE, &opcode, OPCODE_SIZE);
    start_index += OPCODE_SIZE;

    send_buffer.insert(send_buffer.end(), client_nonce.begin(), client_nonce.end());
    start_index += NONCE_SIZE;

    send_buffer.insert(send_buffer.end(), username.begin(), username.end());
    start_index += username.size();

    //sendMsg
    cout << "authentication->sendMsg M1: nonceClient, username " << endl;
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

    ssize_t payload_size;
    uint32_t start_index = 0;
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
        
        clear_vec(recv_buffer);

        return false;
    }

    if(start_index > UINT32_MAX - uint32_t(NONCE_SIZE + NONCE_SIZE) || 
            start_index + uint32_t(NONCE_SIZE + NONCE_SIZE) >= recv_buffer.size()) {
            
        cerr << "Received msg size error" << endl;
        clear_vec(recv_buffer);
        return false;
    }

    // retrieve & check client nonce
    received_nonce.insert(received_nonce.begin(), 
                        recv_buffer.begin() + start_index, 
                        recv_buffer.begin() + start_index + NONCE_SIZE);
    start_index += NONCE_SIZE;

    
    if(!active_session->checkNonce(received_nonce.data(), client_nonce.data())) {
        cerr << "Received nonce not valid\n";

        received_nonce.clear();
        // TODO: check and clear all used buffers
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();    //fill('0');
        
        clear_vec(received_nonce);
        client_nonce.fill('0');
        clear_vec(recv_buffer);

        return false;
    }
    cout << "Received nonce verified!" << endl;

    // retrieve server nonce
    srv_nonce.insert(srv_nonce.begin(), 
                    recv_buffer.begin() + start_index, 
                    recv_buffer.begin() + start_index + NONCE_SIZE);
    //memcpy(srv_nonce.data(), recv_buffer.data() + start_index, NONCE_SIZE);   // server nonce
    start_index += NONCE_SIZE;

    if(start_index > UINT32_MAX - NUMERIC_FIELD_SIZE || 
        start_index + NUMERIC_FIELD_SIZE >= recv_buffer.size()) {
        cerr << "Received msg size error " << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();
        return false;
    }

    // retrieve server cert
    cert_size = *(uint32_t*)(recv_buffer.data() + start_index);
    cert_size = ntohl(cert_size);
    start_index += NUMERIC_FIELD_SIZE;
    
    if(start_index > UINT32_MAX - cert_size || start_index + cert_size >= recv_buffer.size()) {
        
        cerr << "Received msg size error " << endl;
        clear_vec(recv_buffer);
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
        clear_vec(temp_buffer);
        clear_vec(recv_buffer);

        return false;
    }
    cout << "Server certificate verified!" << endl;
    clear_vec(temp_buffer);
    
    if(start_index > UINT32_MAX - NUMERIC_FIELD_SIZE || 
        start_index + NUMERIC_FIELD_SIZE >= recv_buffer.size()) {
        
        cerr << "Received msg size error " << endl;
        clear_vec(recv_buffer);
        return false;
    }

    // retrieve ECDH server pub key: size + key
    ECDH_key_size = *(uint32_t*)(recv_buffer.data() + start_index);
    ECDH_key_size = ntohl(ECDH_key_size);
    start_index += NUMERIC_FIELD_SIZE;
    
    if(start_index > UINT32_MAX - ECDH_key_size ||
        start_index + ECDH_key_size >= recv_buffer.size()) {
        
        cerr << "Received msg size error " << endl;
        clear_vec(recv_buffer);
        return false;
    }

    //get server ECDH key
    ECDH_server_key.insert(ECDH_server_key.begin(), 
                        recv_buffer.begin() + start_index,
                        recv_buffer.begin() + start_index + ECDH_key_size);

    start_index += ECDH_key_size;

    // retrieve digital signature
    dig_sign_len = recv_buffer.size() - start_index;
    if(dig_sign_len <= 0) {
        cerr << "Dig_sign length error " << endl;
        clear_vec(recv_buffer);
        clear_vec(ECDH_server_key);
        return false;
    }

    server_signature.insert(server_signature.begin(), 
                        recv_buffer.begin() + start_index, 
                        recv_buffer.end());
    start_index += dig_sign_len;

    if(payload_size > 0 && uint32_t(payload_size) != start_index - NUMERIC_FIELD_SIZE) {
        cerr << "Received data size error" << endl;
        clear_vec(server_signature);
        clear_vec(ECDH_server_key);
        clear_vec(recv_buffer);
        return false;
    }
    
    /* verify digital signature: | nonce_client | server ECDH key | */
    if(ECDH_key_size > UINT32_MAX - uint32_t(NONCE_SIZE)) {
        cerr << "receiveCertSign -> size overflow " << endl;
        clear_vec(server_signature);
        clear_vec(ECDH_server_key);
        clear_vec(recv_buffer);
        return false;
    }
    signed_msg_len = NONCE_SIZE + ECDH_key_size;

    // nonce client
    clear_vec(temp_buffer);

    temp_buffer.insert(temp_buffer.begin(), client_nonce.begin(), client_nonce.end());
    start_index = NONCE_SIZE;

    // server ECDH public key
    temp_buffer.insert(temp_buffer.end(), ECDH_server_key.begin(), ECDH_server_key.end());
    
    bool verified = active_session->verifyDigSign(server_signature.data(), dig_sign_len, 
                                                    srv_pubK, temp_buffer.data(), signed_msg_len);
    
    // clear buffers    
    clear_vec(temp_buffer);
    clear_vec(server_signature);

    if(!verified) {
        cerr << "Digital Signature not verified" << endl;

        // clear buffer key
        clear_vec(ECDH_server_key);

        return false;
    }
    cout << " Digital Signature Verified!" << endl;
    
    if(active_session->deserializePubKey(ECDH_server_key.data(), ECDH_key_size, active_session->ECDH_peerKey) != 1) {
        cerr << "Error: deserializePubKey failed!" << endl;
        
        clear_vec(ECDH_server_key);
        return false;
    }

    clear_vec(ECDH_server_key);
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

    if(ECDH_my_key_size < 0) {
        cerr << "Error: serializePubKey failed " << endl;
        free(ECDH_my_pub_key);
        return -1;
    }


    cout << "ECDH_my_key_size " << ECDH_my_key_size << endl;
    msg_to_sign.resize(ECDH_my_key_size);
    msg_to_sign.insert(msg_to_sign.begin(), srv_nonce.begin(), srv_nonce.end());
    memcpy(msg_to_sign.data() + NONCE_SIZE, ECDH_my_pub_key, ECDH_my_key_size);
    
    signed_msg_len = active_session->signMsg(msg_to_sign.data(), NONCE_SIZE + ECDH_my_key_size, priv_k, signed_msg.data());

    if( signed_msg_len < 0) {
        cerr << "signMsg failed" << endl;
        free(ECDH_my_pub_key);
        clear_vec(msg_to_sign);
        clear_vec(signed_msg);
        return -1;
    }

    if(uint64_t(signed_msg_len) > uint64_t(UINT32_MAX - OPCODE_SIZE - uint32_t(NONCE_SIZE) -
                                NUMERIC_FIELD_SIZE - ECDH_my_key_size)) {
            
        cerr << "sendSign -> size overflow" << endl;
        // cleaning
        free(ECDH_my_pub_key);
        clear_vec(msg_to_sign);
        clear_vec(signed_msg);
        return -1;
    }
    // prepare send buffer
    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE + NUMERIC_FIELD_SIZE + ECDH_my_key_size);

    payload_size = OPCODE_SIZE + uint32_t(NONCE_SIZE) + NUMERIC_FIELD_SIZE + ECDH_my_key_size + uint32_t(signed_msg_len);
    payload_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_n, NUMERIC_FIELD_SIZE);
    start_index = NUMERIC_FIELD_SIZE;

    opcode = htons((uint16_t)LOGIN);
    memcpy(send_buffer.data() + start_index, &opcode, OPCODE_SIZE);
    start_index += OPCODE_SIZE;

    send_buffer.insert(send_buffer.begin() + start_index, srv_nonce.begin(), srv_nonce.end());
    cout << "serv_nonce inserted" << endl;
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

    // send msg to server
    ret = sendMsg(payload_size);

    // clear buffers      
    free(ECDH_my_pub_key);
    clear_vec(msg_to_sign);
    clear_vec(signed_msg);

    cout << "sendSign end" << endl;

    return ret;
}


/********************************************************************/

bool Client::buildStore(X509*& ca_cert, X509_CRL*& crl, X509_STORE*& store) {
    // load CA certificate
    string ca_cert_filename = "./client/FoundationOfCybersecurity_cert.pem";
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

bool Client::handlerCommand(string& command) {
    if(command.compare("!help") == 0) {
        showCommands();   
    } else if(command.compare("!list") == 0) {
        cout << "FileList operation requested" << endl;
        requestFileList();
    } else if(command.compare("!upload") == 0) {
        cout << "Upload operation requested" << endl;
        uploadFile();
    } else if(command.compare("!download") == 0) {
        cout << "Download operation requested" << endl;
        downloadFile();
    } else if(command.compare("!rename") == 0) {
        cout << "Rename operation requested " << endl;
        renameFile();
    } else if(command.compare("!delete") == 0) {
        cout << "Delete operation requested" << endl;
        deleteFile();
    } else if(command.compare("!exit") == 0) {
        cout << "Logout requested" << endl; 
        logout();    
        return false;    
    } else {
        cout << "Invalid command\nRetry" << endl;
        showCommands();
    }
    return true;
}

int Client::requestFileList() {
    string msg = this->username;
    uint32_t payload_size, payload_size_n;
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext;
    array<unsigned char, MAX_BUF_SIZE> output;

    cout<<"****************************************"<<endl;
    cout<<"******     Request File List      ******"<<endl;
    cout<<"****************************************"<<endl;


    plaintext.insert(plaintext.begin(), msg.begin(), msg.end());

    this->active_session->createAAD(aad.data(), FILE_LIST);
    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), 
                                                        aad.data(), output.data());
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        clear_vec(plaintext);
        clear_vec(send_buffer);
        clear_arr(aad.data(), aad.size());
        clear_arr(output.data(), output.size());
        return -1;
    }
    payload_size_n = htonl(payload_size);
        
    clear_vec(plaintext);
    clear_vec(send_buffer);
    clear_arr(aad.data(), aad.size());

    send_buffer.resize(NUMERIC_FIELD_SIZE);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), 
                            output.begin() + payload_size);

    clear_arr(output.data(), output.size());

    if(sendMsg(payload_size) != 1){
        cerr<<"Error during send phase (C->S | File List Request)"<<endl;
        clear_vec(send_buffer);
        return -1;
    }

    clear_vec(send_buffer);

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
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(MAX_BUF_SIZE);
    long received_len;
    uint32_t pt_len;
    uint16_t opcode;
    string filelist = "";

    while(true) {
        received_len = receiveMsg();
        if(received_len <= 0 || (received_len > 0 && uint32_t(received_len) < MIN_LEN)) {
            cerr<<"Error! Exiting receive file list phase"<<endl;
            clear_vec(recv_buffer);
            return -1;
        }

        pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len,
                                                    aad.data(), plaintext.data());
        if (pt_len == 0){
            cerr << "Error during decryption! File list phase" << endl;
            clear_vec(plaintext);
            clear_vec(recv_buffer);
            clear_arr(aad.data(), aad.size());
            return -1;
        }

        clear_vec(recv_buffer);
        opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));

        if(opcode == FILE_LIST)
            cout << string(plaintext.begin(), plaintext.end());
        else if(opcode == END_OP){
            cout << string(plaintext.begin(), plaintext.begin() + (pt_len))<<endl;
            break;
        }
        else{
            cerr<<"Error! The received file list chunk was malformed"<<endl;
            clear_vec(plaintext);
            clear_arr(aad.data(), aad.size());
            return -1;
        }

        clear_vec(plaintext);
        clear_arr(aad.data(), aad.size());
    }
    return 0;
}

void Client::logout() {
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(FILE_SIZE_FIELD);
    array<unsigned char, MAX_BUF_SIZE> output;
    uint32_t payload_size, payload_size_n;
    string msg = CLIENT_LOGOUT;

    cout<<"****************************************"<<endl;
    cout<<"******       Client Logout        ******"<<endl;
    cout<<"****************************************"<<endl;

    plaintext.insert(plaintext.begin(), msg.begin(), msg.end());
    this->active_session->createAAD(aad.data(), LOGOUT);

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), 
                                                        aad.data(), output.data());
    clear_vec(plaintext);
    clear_vec(send_buffer);
    clear_arr(aad.data(), aad.size());
    if (payload_size == 0){
        cerr<<"Error! The received file list chunk was malformed"<<endl;
        exit(EXIT_FAILURE);
    }
    payload_size_n = htonl(payload_size);

    send_buffer.resize(NUMERIC_FIELD_SIZE);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), 
                            output.begin() + payload_size);

    clear_arr(output.data(), output.size());
    if (sendMsg(payload_size) != 1){
        cerr<<"Error during logout phase!"<<endl;
        clear_vec(send_buffer);
        exit(EXIT_FAILURE);
    }
    clear_vec(send_buffer);

    long received_len;
    int pt_len;
    uint16_t opcode;

    received_len = receiveMsg();
    if(received_len <= 0) {
        cerr << "Error on the receiveMsg -> closing connection..." << endl;
        exit(EXIT_FAILURE);
    }
    if(uint32_t(received_len) >= MIN_LEN) {
        pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len, 
                                                    aad.data(), plaintext.data());

        if(pt_len != 0) {
            opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
            clear_vec(recv_buffer);
            clear_arr(aad.data(), aad.size());

            if(opcode == END_OP)
                cout << string(plaintext.begin(), plaintext.begin() + pt_len) << endl;
            else{
                clear_vec(plaintext);
                cerr <<"Error! Unexpected message" << endl;
                exit(EXIT_FAILURE);
            }

            clear_vec(plaintext);
        }
        else{
            clear_arr(aad.data(), aad.size());
            clear_vec(plaintext);
            clear_vec(recv_buffer);
            cerr << "Error during decryption" << endl;
            exit(EXIT_FAILURE);
        }
    }
    else{
        clear_vec(recv_buffer);
        cerr << "Error during receive phase (S->C, logout)" << endl;
        exit(EXIT_FAILURE);
    }
    cout<<"****************************************"<<endl;
    cout<<"******     Client Logged Out      ******"<<endl;
    cout<<"****************************************"<<endl;
}

uint32_t Client::sendMsgChunks(string filename){
    string path = FILE_PATH_CLIENT + this->username + "/" + filename;
    FILE* file = fopen(path.c_str(), "rb");
    struct stat buf;

    if(!file){
        cerr << "Error during file opening. "<<endl;
        return -1;
    }

    if(stat(path.c_str(), &buf) != 0){
        cerr << filename + "doesn't exist in " + this->username + "folder" << endl;
        return -1;
    }

    uint32_t tot_chunks = ceil((float)buf.st_size / FRAGM_SIZE);                          //total number of chunks needed form the upload
    size_t ret, to_send;                                                                     //number of byte to send in the specific msg
    uint32_t payload_size, payload_size_n;                                       //bytes read by the fread function
    array<unsigned char, AAD_LEN> aad;                                                          //aad of the msg
    array<unsigned char, FRAGM_SIZE> frag_buffer;                                       //msg to be encrypted
    array<unsigned char, MAX_BUF_SIZE> output;                                          //encrypted text
 
    clear_vec(send_buffer);
    clear_arr(frag_buffer.data(), frag_buffer.size());

    for(uint32_t i = 0; i < tot_chunks; i++) {
        cout << "Chunk n: " << i + 1 << " of " << tot_chunks << endl;
        if(i == tot_chunks - 1){
            to_send = buf.st_size - i * FRAGM_SIZE;
            this->active_session->createAAD(aad.data(), END_OP);
        }
        else{
            to_send = FRAGM_SIZE;
            this->active_session->createAAD(aad.data(), UPLOAD);
        }

        ret = fread(frag_buffer.data(), sizeof(char), to_send, file);

        if(ferror(file) != 0 || ret != to_send){
            cerr<<"ERROR while reading file"<<endl;
            return -1;
        }

        payload_size = this->active_session->encryptMsg(frag_buffer.data(), to_send, 
                                                            aad.data(), output.data());
        clear_arr(aad.data(), aad.size());
        clear_arr(frag_buffer.data(), frag_buffer.size());

        if (payload_size == 0) {
            cerr << " Error during encryption. Send msg chunk phase" << endl;
            clear_arr(output.data(), output.size());
            return -1;
        }
        send_buffer.resize(NUMERIC_FIELD_SIZE);

        payload_size_n = htonl(payload_size);
        memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
        send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), 
                                output.begin() + payload_size);
        
        clear_arr(output.data(), output.size());

        if(sendMsg(payload_size) != 1){
            cerr<<"Error during send phase (C->S) | Upload Chunk Phase (chunk num: "<<i<<")"<<endl;
            clear_vec(send_buffer);
            return -1;
        }

        clear_vec(send_buffer);
    }
    return 1;
}



int Client::uploadFile(){
    long file_dim;
    uint32_t payload_size, payload_size_n;
    uint32_t file_dim_l_n, file_dim_h_n;
    string filename;
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(FILE_SIZE_FIELD);
    array<unsigned char, MAX_BUF_SIZE> output;

    cout<<"****************************************"<<endl;
    cout<<"*********     UPLOAD FILE      *********"<<endl;
    cout<<"****************************************"<<endl<<endl;

    readFilenameInput(filename, "Insert filename: ");
    file_dim = searchFile(filename, this->username, CLIENT_SIDE);

    if(file_dim < 0 && file_dim != -1 && file_dim != -3){
        cerr << "File is too big! Upload terminated ---- " << file_dim << endl;
        return -1;
    }
    else if  (file_dim == -1){
        cerr << "File not found! Upload not possible" << endl;
        return -1;
    }
    else if (file_dim == -3){
        cerr << "Invalid path! Upload terminated" << endl;
        return -1;
    }                   

    file_dim_h_n = htonl((uint32_t) (file_dim >> 32));
    file_dim_l_n = htonl((uint32_t) (file_dim));
    memcpy(plaintext.data(), &file_dim_l_n, NUMERIC_FIELD_SIZE);
    memcpy(plaintext.data() + NUMERIC_FIELD_SIZE, &file_dim_h_n, NUMERIC_FIELD_SIZE);
    plaintext.insert(plaintext.begin() + FILE_SIZE_FIELD, filename.begin(), filename.end());  

    this->active_session->createAAD(aad.data(), UPLOAD_REQ);                

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    clear_arr(aad.data(), aad.size());
    clear_vec(plaintext);

    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;     
        clear_arr(output.data(), output.size());
        return -1;
    }
    payload_size_n = htonl(payload_size);

    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    clear_vec(send_buffer);
    if(sendMsg(payload_size) != 1){
        cerr<<"Error during send phase (C->S | Upload Request Phase)"<<endl;
        clear_arr(output.data(), output.size());
        return -1;
    }

    clear_arr(output.data(), output.size());

    int pt_len;                                                          
    uint16_t opcode;
    uint32_t ret;  
    long received_len;
    string server_response;

    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len <= 0 ||
        (received_len > 0 && uint32_t(received_len) < MIN_LEN)){
        cerr<<"Error during receive phase (S->C, upload)"<<endl;
        clear_vec(recv_buffer);
        return -1;
    }

    pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
    clear_vec(recv_buffer);
    if (pt_len == 0) {
        cerr << " Error during decryption" << endl;
        clear_vec(plaintext);
        clear_arr(aad.data(), aad.size());
        return -1;
    }

    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
    clear_arr(aad.data(), aad.size());
    if(opcode != UPLOAD_REQ){
        cerr<<"Error! Exiting upload request phase"<<endl;
        clear_vec(plaintext);
        return -1;
    }
    
    server_response = ((char*)plaintext.data());
    clear_vec(plaintext);
    if(server_response == FILE_PRESENT){      
        cout << "File not accepted. " << server_response << endl;
        return 1;
    }
    if(server_response == MALFORMED_FILENAME){
        cerr << "File not accepted. " << server_response << endl;
        return -1;
    }
   
    cout<<"*****           UPLOADING          *****"<<endl;
    
    clear_vec(send_buffer);

    ret = sendMsgChunks(filename);

    if(ret == 1){
        plaintext.resize(MAX_BUF_SIZE);        
        received_len = receiveMsg();
        if(received_len <= 0 ||
            (received_len > 0 && uint32_t(received_len) < MIN_LEN)) {
        cerr<<"Error during receive phase (S->C)"<<endl;
        clear_vec(recv_buffer);
        return -1;
        }
        
        pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
        clear_vec(recv_buffer);
        if (pt_len == 0) {
            cerr << " Error during decryption" << endl;
            clear_vec(plaintext);
            clear_arr(aad.data(), aad.size());
            return -1;
        }

        opcode = ntohs(*(uint16_t*)(aad.data() + sizeof(uint32_t)));
        clear_arr(aad.data(), aad.size());
        if(opcode != END_OP){
            cerr<<"Error! Exiting upload phase." << endl;
            clear_vec(plaintext);
            return -1;
        }

        server_response = string(plaintext.begin(), plaintext.begin() + pt_len);
        clear_vec(plaintext);
        if(server_response != OP_TERMINATED){
            cerr<<"Upload not correcty terminated. "<< server_response <<endl;
            return -1;
        }
    }
    else{
        cerr<<"Error! Exiting upload phase"<<endl;
        return -1;
    }

    cout<<"****************************************"<<endl;
    cout<<"*****       UPLOAD TERMINATED      *****"<<endl;
    cout<<"****************************************"<<endl;

    return 1;
}


int Client::renameFile(){

    string old_filename, new_filename;
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(2 * NUMERIC_FIELD_SIZE);
    array<unsigned char, MAX_BUF_SIZE> output;
    uint32_t old_filename_lenght, old_filename_lenght_n;
    uint32_t new_filename_lenght, new_filename_lenght_n;
    uint32_t payload_size, payload_size_n;

    cout<<"****************************************"<<endl;
    cout<<"*********     RENAME FILE      *********"<<endl;
    cout<<"****************************************"<<endl;

    readFilenameInput(old_filename, "Insert the name of the file to be changed: ");
    readFilenameInput(new_filename, "Insert the new name of the file: ");

    old_filename_lenght = old_filename.size();
    new_filename_lenght = new_filename.size();

    old_filename_lenght_n = htonl(old_filename_lenght);
    new_filename_lenght_n = htonl(new_filename_lenght);

    memcpy(plaintext.data(), &old_filename_lenght_n, NUMERIC_FIELD_SIZE);
    memcpy(plaintext.data() + NUMERIC_FIELD_SIZE, &new_filename_lenght_n, NUMERIC_FIELD_SIZE);
    plaintext.insert(plaintext.begin() + 2 * NUMERIC_FIELD_SIZE, old_filename.begin(), old_filename.end());
    plaintext.insert(plaintext.begin() + 2 * NUMERIC_FIELD_SIZE + old_filename_lenght, new_filename.begin(), new_filename.end());

    this->active_session->createAAD(aad.data(), RENAME_REQ);

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    clear_vec(plaintext);
    clear_arr(aad.data(), aad.size());

    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        clear_arr(output.data(), output.size());
        return -1;
    }
    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    clear_arr(output.data(), output.size());

    if(sendMsg(payload_size) != 1){
        cerr<<"Error during send phase (C->S | Rename Request Phase)"<<endl;
        clear_vec(send_buffer);
        return -1;
    }

    clear_vec(send_buffer);
    plaintext.resize(MAX_BUF_SIZE);

    uint16_t opcode;
    long received_len;
    int pt_len;
    string server_response;

    received_len = receiveMsg();
    if(received_len <= 0 ||
        (received_len > 0 && uint32_t(received_len) < MIN_LEN)){
        cerr <<"Error during receive phase (S->C, rename)";
        clear_vec(recv_buffer);
        return -1;
    }

    pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
    clear_vec(recv_buffer);
    if (pt_len == 0) {
        cerr << " Error during decryption" << endl;
        clear_vec(plaintext);
        clear_arr(aad.data(), aad.size());
        return -1;
    }

    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
    clear_arr(aad.data(), aad.size());
    if(opcode != END_OP){
        cerr << "Error! Exiting rename request phase"<<endl;
        clear_vec(plaintext);
        return -1;
    }

    server_response = ((char*)plaintext.data());
    clear_vec(plaintext);
    if(server_response != MESSAGE_OK){
        cerr << "Rename not accepted. "<< server_response <<endl;
        return -1;
    }

    cout<<"****************************************"<<endl;
    cout<<"******     Rename Terminated      ******"<<endl;
    cout<<"****************************************"<<endl;

    return 1;
}


//---------------------------------------------//

int Client::receiveMsgChunks( uint32_t filedimension, string filename)
{
    string path = FILE_PATH_CLIENT + this->username + "/" + filename;
    ofstream outfile(path, ofstream::binary);

    array<unsigned char, AAD_LEN> aad;
    array<unsigned char, MAX_BUF_SIZE> plaintext;

    size_t to_receive;
    long received_len;
    uint32_t opcode, pt_len;

    uint32_t tot_chunks = ceil((float)filedimension / FRAGM_SIZE);

    for(int i = 0; i < tot_chunks; i++){
        if(i == tot_chunks - 1)
            to_receive = filedimension - i * FRAGM_SIZE;
        else
            to_receive = FRAGM_SIZE;

        received_len = receiveMsg();

        if(received_len <= 0)
        {
            cerr<<"Error! Exiting receive phase"<<endl;
            clear_vec(recv_buffer);
            return -1;
        }
        
        pt_len = this->active_session->decryptMsg(this->recv_buffer.data(),
                                received_len, aad.data(), plaintext.data());
        clear_vec(recv_buffer);
        
        if (pt_len == 0) {
            cerr << " Error during decryption" << endl;
            clear_arr(plaintext.data(), plaintext.size());    
            clear_arr(aad.data(), aad.size());
            return -1;
        }

        opcode = ntohs(*(uint32_t*)(aad.data() + NUMERIC_FIELD_SIZE));
        clear_arr(aad.data(), aad.size());
        
        if((opcode == DOWNLOAD_REQ && i == tot_chunks - 1) || (opcode == END_OP && i != tot_chunks - 1)){
            outfile.close();
            cerr << "Wrong message format. Exiting"<<endl;
            clear_arr(plaintext.data(), plaintext.size());
            
            if(remove(path.c_str()) != 0)
                cerr << "File not correctly cancelled"<<endl;
            
            return -1;
        }

        outfile << string(plaintext.begin(), plaintext.begin() + pt_len);
        clear_arr(plaintext.data(), plaintext.size());
        clear_arr(aad.data(), aad.size());
        outfile.flush();
    }

    clear_arr(aad.data(), aad.size());
    clear_arr(plaintext.data(), plaintext.size());
    outfile.close();
    return 1;
}

int Client::downloadFile()
{
    string filename;
    uint32_t filename_size, filename_size_n, payload_size, payload_size_n, filedimension;   
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(NUMERIC_FIELD_SIZE);
    array<unsigned char, MAX_BUF_SIZE> ciphertext;

    readFilenameInput(filename, "Insert the name of the file you want to Download: ");

    // === Checking and managing the existence of the file within the Download folder ===
    if (searchFile(filename, this->username, CLIENT_SIDE) >= 0){
        string choice;

        cout << "The requested file already exists in the Download folder, "
        << "do you want to overwrite it?: [y/n]\n"<<endl;
        cout<<"_Ans: ";
        getline(cin, choice);

        if(!cin)
            cerr << "\n === Error during input ===\n" << endl; return -1;

        while(choice != "Y" && choice!= "y" && choice != "N" && choice!= "n" ){
            cout << "\nError: Type Y/y or N/n!" << endl <<"Try again: [y/n] ";
            getline(cin, choice);

            if(!cin){
                cerr << "\n === Error during input ===\n" << endl;
                return -1;
            }
        }
        if(choice == "N" || choice == "n"){
            cout<<"\n\t~ The file *( "<< filename << " )* will not be overwritten. ~\n\n"<<endl;
            return -1;
        }
        
        if(removeFile(filename, this->username, CLIENT_SIDE) != 1){
            cout << "\n\t --- Error during Deleting file ---\n" << endl;
            return -1; 
        }
    }
    
    // === Preparing Data Sending and Encryption ===
    filename_size = filename.size();
    filename_size_n = htonl(filename_size);
    memcpy(plaintext.data(), &filename_size_n, NUMERIC_FIELD_SIZE);
    plaintext.insert(plaintext.begin() + NUMERIC_FIELD_SIZE, filename.begin(), filename.begin() + filename.size());

    this->active_session->createAAD(aad.data(), DOWNLOAD_REQ);
    
    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                                    aad.data(), ciphertext.data());
    clear_vec(plaintext);
    clear_arr(aad.data(), aad.size());
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        clear_arr(ciphertext.data(), ciphertext.size());
        return -1;
    }
    clear_vec(plaintext);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);

    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, ciphertext.begin(),
                        ciphertext.begin() + payload_size);
    clear_arr(ciphertext.data(), ciphertext.size());


// _BEGIN_(1)-------------- [ M1: INVIO_RICHIESTA_DOWNLOAD_AL_SERVER ] --------------

    if(sendMsg(payload_size) != 1)
    {
        cout<<"Error during send phase (C->S)"<<endl;
        clear_vec(send_buffer);
        return -1;
    }

// _END_(1))-------------- [ M1: INVIO_RICHIESTA_DOWNLOAD_AL_SERVER ] --------------  

    uint16_t opcode;
    uint64_t received_len;  //Legnht of the message received from the server 
    uint32_t plaintext_len;
    string server_response; //Message from the server containing the response to the request
    int fileChunk; //Management Chunk

    // === Reuse of vectors declared at the beginning ===
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len <= 0)
    {
        cout<<"Error during receive phase (S->C)"<<endl;
        clear_vec(recv_buffer);
        return -1;
    }

    //received from server in terms of byte
    plaintext_len = this->active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), plaintext.data());
    clear_vec(recv_buffer);
    if (plaintext_len == 0) {
        cerr << " Error during decryption" << endl;
        clear_vec(plaintext);
        clear_arr(aad.data(), aad.size());
        return -1;
    }
    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE)); 
    clear_arr(aad.data(), aad.size());   
    if(opcode != DOWNLOAD_REQ)
    {
        cout<<"Error! Exiting download request phase"<<endl;
        clear_vec(plaintext);
        return -1;
    }

// _BEGIN_(2)------ [M2: RICEZIONE_CONFERMA_RICHIESTA_DOWNLOAD_DAL_SERVER ] ------
    
    /*--- Check Response file existence in the Cloud Storage by the Server ---*/
    filedimension = ntohl(*(uint32_t*)plaintext.data());
    server_response.insert(server_response.begin(), plaintext.begin() + NUMERIC_FIELD_SIZE, plaintext.begin() + plaintext_len);    
    clear_vec(plaintext);

    if(server_response != MESSAGE_OK){       
        cout<<"The file cannot be downloaded: "<< server_response <<endl;
        return -1;
    }
    
// _END_(2)------ [ M2: RICEZIONE_CONFERMA_RICHIESTA_DOWNLOAD_DAL_SERVER ] )------

    cout << "\nThe requested file is in the cloud storage and can be downloaded."<<endl;
    cout<<"\n\t ...Download file " + filename +" in progress...\n\n"<<endl;    

// _BEGIN_(3)-------------- [ M3: RICEZIONE_FILE_DAL_SERVER ] --------------

    fileChunk = receiveMsgChunks(filedimension, filename);

    if(fileChunk == -1){
        cout<<"Error! Exiting Download phase"<<endl;      
        return -1;
    }

// _END_(3)-------------- [ M3: RICEZIONE_FILE_DAL_SERVER ] --------------
    
    cout << "\n\tFile Download Completed!" << endl;

    // === Preparing Data Sending and Encryption ===    
    this->active_session->createAAD(aad.data(), END_OP);
    string ack_msg = DOWNLOAD_TERMINATED;
    
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                                    aad.data(), ciphertext.data());
    clear_vec(plaintext);
    clear_arr(aad.data(), aad.size());
    
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        clear_arr(ciphertext.data(), ciphertext.size());
        return -1;
    }
    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin()+ NUMERIC_FIELD_SIZE, ciphertext.begin(),
                        ciphertext.begin() + payload_size);
    clear_arr(ciphertext.data(), ciphertext.size());

// _BEGIN_(4)-------------- [ M4: INVIO_CONFERMA_DOWNLOAD_AL_SERVER ] --------------

    if(sendMsg(payload_size) != 1){
        cout<<"Error during send phase (C->S)"<<endl;
        clear_vec(send_buffer);
        return -1;
    }
    
// _END_(4)-------------- [ M4: INVIO_CONFERMA_DOWNLOAD_AL_SERVER ] --------------
    
    return 1;
}

int Client::deleteFile()
{
    string filename;
    uint32_t payload_size, payload_size_n;   
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext;
    array<unsigned char, MAX_BUF_SIZE> ciphertext;

// _BEGIN_(1)-------------- [ M1: SEND_DELETE_REQUEST_TO_SERVER ] --------------

    readFilenameInput(filename, "Insert the name of the file you want to delete: ");

    // === Preparing Data Sending and Encryption  ===
    plaintext.insert(plaintext.begin(), filename.begin(), filename.end());
    this->active_session->createAAD(aad.data(), DELETE_REQ);
    
    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                                    aad.data(), ciphertext.data());
    // === Cleaning ===
    clear_vec(plaintext);
    clear_arr(aad.data(), aad.size());

    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        clear_arr(ciphertext.data(), ciphertext.size());
     
        return -1;
    }

    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, 
                        ciphertext.begin(), ciphertext.begin() + payload_size);
    clear_arr(ciphertext.data(), ciphertext.size());

    if(sendMsg(payload_size) != 1){
        cout<<"Error during send phase (C->S)"<<endl;
        clear_vec(send_buffer);
        return -1;
    }

// _END_(1))-------------- [ M1: SEND_DELETE_REQUEST_TO_SERVER ] --------------


// _BEGIN_(2)------ [M2: RECEIVE_CONFIRMATION_DELETE_REQUEST_FROM_SERVER ] ------

    uint16_t opcode;
    long received_len;  
    uint32_t pt_len;
    string server_response, choice; 

    // === Reuse of vectors declared at the beginning ===
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len <= 0){
        cout<<"Error during receive phase (S->C)"<<endl;
        clear_vec(recv_buffer);
        return -1;
    }

    //received from server in terms of byte
    pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), plaintext.data());
    clear_vec(recv_buffer);

    if (pt_len == 0) {
        cerr << " Error during decryption" << endl;
        clear_vec(plaintext);
        clear_arr(aad.data(), aad.size());
        return -1;
    }

    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));    
    clear_arr(aad.data(), aad.size());

    if(opcode != DELETE_REQ){
        cout<<"Error! Exiting DELETE request phase"<<endl;
        clear_vec(plaintext);
        return -1;
    }
    
    /*--- Check Response existence of file in the Cloud Storage by the Server ---*/
    server_response = ((char*)plaintext.data());
    clear_vec(plaintext);

    if(server_response != MESSAGE_OK){       
        cout << "The delete request was refused: " << server_response << endl;
        return -1;
    }
    
// _END_(2)-------- [ M2: RECEIVE_CONFIRMATION_DELETE_REQUEST_FROM_SERVER ] --------
    
    cout << "Are you sure to delete the file " << filename << "?: [y/n]\n" <<endl;
    getline(cin, choice);

    if(!cin){
        cerr << "\n === Error during input ===\n" << endl;
        return -1;
    }

    while(choice != "Y" && choice!= "y" && choice != "N" && choice!= "n" ){
        cout << "\nError: Type Y/y or N/n!" << endl <<"Try again: [y/n] ";
        getline(cin, choice);

        if(!cin){
            cerr << "\n === Error during input ===\n" << endl;
            return -1;
        }
    }

    if(choice == "N" || choice == "n") {
        cout << "\n\t The file '" << filename << "' will not be deleted. \n"<<endl;
    }
        
    
// _BEGIN_(3)-------------- [ M3: SEND_USER-CHOICE_TO_SERVER ] --------------

    // === Preparing Data Sending and Encryption ===    
    this->active_session->createAAD(aad.data(), DELETE_CONFIRM);
    
    plaintext.insert(plaintext.begin(), choice.begin(), choice.end());

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                                    aad.data(), ciphertext.data());
    clear_vec(plaintext);
    clear_arr(aad.data(), aad.size());
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        clear_arr(ciphertext.data(), ciphertext.size());
        return -1;
    }
    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE,
                        ciphertext.begin(), ciphertext.begin() + payload_size);
    clear_arr(ciphertext.data(), ciphertext.size());

    if(sendMsg(payload_size) != 1){
        cout<<"Error during send phase (C->S)"<<endl;
        clear_vec(send_buffer);
        return -1;
    }

    clear_vec(send_buffer);
    
// _END_(3)-------------- [ M3: SEND_USER-CHOICE_TO_SERVER] --------------


//_BEGIN_(4)---------- [M4: RECEIVE_CONFIRMATION_DELETE_OPERATION_FROM_SERVER ] ----------

    // === Reuse of vectors declared at the beginning ===
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len <= 0){
        cout<<"Error during receive phase (S->C)"<<endl;
        clear_vec(recv_buffer) ;
        return -1;
    }

    //received from server in terms of byte
    pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), plaintext.data());
    clear_vec(recv_buffer);

    if (pt_len == 0) {
        cerr << " Error during decryption" << endl;
        clear_vec(plaintext);
        clear_arr(aad.data(), aad.size());
        return -1;
    }

    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
    clear_arr(aad.data(), aad.size()) ;

    if(opcode != END_OP){
        cout<<"Error! Exiting DELETE phase"<<endl;
        clear_vec(plaintext);
        return -1;
    }
    
    server_response = ((char*)plaintext.data());
    clear_vec(plaintext);
    cout<<"\nEND_DELETE_OPERATION_MSG: "<< server_response <<endl;

//_END_(4)----------- [ M4: RECEIVE_CONFIRMATION_DELETE_OPERATION_FROM_SERVER ] -----------    
    return 1;
}