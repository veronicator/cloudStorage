#include "client.h"

Client::Client(string username, string srv_ip) {
    this->username = username;
    active_session = new Session();

    if (!createSocket(srv_ip)) {
        handleErrors("Socket creation error");
    };
}

Client::~Client() {
    //cout << "~Client" << endl;
    
    delete active_session;

    username.clear();
    clear_vec(send_buffer);
    clear_vec(recv_buffer);
    close(sd);
}

bool Client::createSocket(string srv_ip) {
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {  // socket TCP
        return false;
    }
    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = htons(SRV_PORT);
    if (inet_pton(AF_INET, srv_ip.c_str(), &sv_addr.sin_addr) != 1) {
        cerr << "Server IP not valid" << endl;
        return false;
    }
    if (connect(sd, (struct sockaddr*)&sv_addr, sizeof(sv_addr)) != 0) {
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

    if (payload_size > MAX_BUF_SIZE - NUMERIC_FIELD_SIZE) {
        cerr << "Message to send too big" << endl;
        clear_vec(send_buffer);
        return -1;
    }
    payload_size += NUMERIC_FIELD_SIZE;
    payload_size_n = htonl(payload_size);

    memcpy(arr.data(), &payload_size_n, NUMERIC_FIELD_SIZE);

    ret = send(sd, arr.data(), NUMERIC_FIELD_SIZE, 0);

    if (ret < 0 || (ret >= 0 && size_t(ret) < NUMERIC_FIELD_SIZE)) {
        perror("Error sending message size");
        clear_vec(send_buffer);
        return -1;
    }
    arr.fill('0');

    ret = send(sd, send_buffer.data(), payload_size, 0);
    if (ret < 0 || (ret >= 0 && size_t(ret) < payload_size)) {
        perror("Socker error: send message failed");
        clear_vec(send_buffer);
        return -1;
    }
    
    clear_vec(send_buffer);

    return 1;    
 }

/**
 * receive message from server
 * @return: return the payload length of the received message, or 0 or -1 on error
*/
 long Client::receiveMsg() {

    array<unsigned char, MAX_BUF_SIZE> receiver;
    ssize_t received_partial = 0, recv_byte = 0;
    uint32_t payload_size;

    clear_vec(recv_buffer);

    received_partial = recv(sd, receiver.data(), NUMERIC_FIELD_SIZE, 0);

    payload_size = *(uint32_t*)(receiver.data());
    payload_size = ntohl(payload_size);

    if (payload_size > size_t(MAX_BUF_SIZE - 1)) {
        cerr << "Error: receiveMsg -> size overflow" << endl;
        receiver.fill('0');
        return -1;
    }

    do{
        received_partial = recv(sd, receiver.data() + recv_byte, payload_size - recv_byte, 0);
        recv_byte += received_partial;
    }
    while(recv_byte < payload_size || received_partial <= 0);

    if (received_partial == 0) {
        cerr << "The connection has been closed" << endl;
        return 0;
    }

    if (received_partial < 0 || 
        (recv_byte >= 0 && size_t(recv_byte) < size_t(NUMERIC_FIELD_SIZE + OPCODE_SIZE))) {
        perror("Socket error: receive message failed");
        receiver.fill('0');
        return -1;
    }

    payload_size = *(uint32_t*)(receiver.data());
    payload_size = ntohl(payload_size);

    //check if all data were received
    if (payload_size != size_t(recv_byte) - NUMERIC_FIELD_SIZE) {
        cerr << "Error: Data received too short (malformed message?)" << endl;
        receiver.fill('0');
        return -1;
    }

    recv_buffer.insert(recv_buffer.begin(), receiver.begin(), receiver.begin() + recv_byte);
    receiver.fill('0');     // clear content of the temporary receiver buffer

    return payload_size;

 }

/********************************************************************/


bool Client::authentication() {    
    int ret;
    array<unsigned char, NONCE_SIZE> client_nonce;
    vector<unsigned char> server_nonce;

    EVP_PKEY *my_priv_key;

    /* M1: sending client username to the server */
    if (sendUsername(client_nonce) != 1) {
        cerr << "Authentication->sendUsername phase failed" << endl;
        client_nonce.fill('0');
        return false;
    }
    
    /* M2: receive server certificate and ECDH_server_key */
    if (!receiveCertSign(client_nonce, server_nonce)) {
        cerr << "Authentication->receiveCertSign failed" << endl;
        client_nonce.fill('0');
        clear_vec(server_nonce);
        return false;
    }
    
    client_nonce.fill('0');
    
    my_priv_key = active_session->retrievePrivKey("./client/users/" + username + "/" + username + "_key.pem");
    if (my_priv_key == nullptr) {
        cerr << "retrievePrivKey failed" << endl;
        EVP_PKEY_free(my_priv_key);
        clear_vec(server_nonce);
        return false;
    }
    active_session->generateECDHKey();
    ret = sendSign(server_nonce, my_priv_key);
    server_nonce.clear();
    if (ret != 1) {
        cerr << "sendSign failed " << endl;
        clear_vec(server_nonce);
        EVP_PKEY_free(my_priv_key);
        return false;
    }

    if (active_session->deriveSecret() != 1) {     // derive secrete & compute session key
        clear_vec(server_nonce);
        EVP_PKEY_free(my_priv_key);
        return false;
    }
    EVP_PKEY_free(my_priv_key);
    
    return receiveFileList() != -1;
}

/********************************************************************/

/** Message M1: sending the <username> to the server
 * @client_nonce: nonce of the connected client, to prevent a reply attack
 * @return: 1 on success, -1 on failure
*/
int Client::sendUsername(array<unsigned char, NONCE_SIZE> &client_nonce) {
    uint32_t start_index = 0;
    uint32_t payload_size, payload_n;
    uint16_t opcode;

    if (active_session->generateNonce(client_nonce.data()) != 1) {
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

    if (sendMsg(payload_size) != 1) {
        client_nonce.fill('0');
        return -1;
    }

    return 1;
}

/** Message M2: receive the certification and the digital signature of the server
 * @client_nonce: nonce of the client previously sent, to compare with the one received from the server
 * @server_nonce: vector where store the server nonce received (it will be checked in another method)
 * @return: true on success, false on failure
*/
bool Client::receiveCertSign(array<unsigned char, NONCE_SIZE> &client_nonce, 
                                vector<unsigned char> &srv_nonce) {

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
    if (payload_size <= 0) {
        cerr << "Error on the receiveMsg -> closing connection..." << endl;
        return false;
    }
    
    start_index = NUMERIC_FIELD_SIZE;   // reading starts after payload_size field

    // check opcode
    opcode = *(uint16_t*)(recv_buffer.data() + start_index);
    opcode = ntohs(opcode);
    start_index += OPCODE_SIZE;
    if (opcode != LOGIN) {
        if (opcode == ERROR) {
            string errorMsg(recv_buffer.begin() + start_index, recv_buffer.end());
            cerr << errorMsg << endl;
        } else {
            cerr << "Received not expected message" << endl;
        }
        
        clear_vec(recv_buffer);

        return false;
    }

    if (start_index > UINT32_MAX - uint32_t(NONCE_SIZE + NONCE_SIZE) || 
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

    
    if (!active_session->checkNonce(received_nonce.data(), client_nonce.data())) {
        cerr << "Received nonce not valid\n";

        clear_vec(recv_buffer);
        clear_vec(received_nonce);
        client_nonce.fill('0');

        return false;
    }
    cout << "Received nonce verified!" << endl;

    // retrieve server nonce
    srv_nonce.insert(srv_nonce.begin(), 
                    recv_buffer.begin() + start_index, 
                    recv_buffer.begin() + start_index + NONCE_SIZE);
    //memcpy(srv_nonce.data(), recv_buffer.data() + start_index, NONCE_SIZE);   // server nonce
    start_index += NONCE_SIZE;

    if (start_index > UINT32_MAX - NUMERIC_FIELD_SIZE || 
        start_index + NUMERIC_FIELD_SIZE >= recv_buffer.size()) {
        cerr << "Received msg size error " << endl;
        clear_vec(recv_buffer);
        return false;
    }

    // retrieve server cert
    cert_size = *(uint32_t*)(recv_buffer.data() + start_index);
    cert_size = ntohl(cert_size);
    start_index += NUMERIC_FIELD_SIZE;
    
    if (start_index > UINT32_MAX - cert_size || start_index + cert_size >= recv_buffer.size()) {
        
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
    if (!verifyCert(temp_buffer.data(), cert_size, srv_pubK)) {
        
        cerr << "Server certificate not verified\n";
        clear_vec(temp_buffer);
        clear_vec(recv_buffer);
        EVP_PKEY_free(srv_pubK);

        return false;
    }
    cout << "Server certificate verified!" << endl;
    clear_vec(temp_buffer);
    
    if (start_index > UINT32_MAX - NUMERIC_FIELD_SIZE || 
        start_index + NUMERIC_FIELD_SIZE >= recv_buffer.size()) {
        
        cerr << "Received msg size error " << endl;
        clear_vec(recv_buffer);
        EVP_PKEY_free(srv_pubK);
        return false;
    }

    // retrieve ECDH server pub key: size + key
    ECDH_key_size = *(uint32_t*)(recv_buffer.data() + start_index);
    ECDH_key_size = ntohl(ECDH_key_size);
    start_index += NUMERIC_FIELD_SIZE;
    
    if (start_index > UINT32_MAX - ECDH_key_size ||
        start_index + ECDH_key_size >= recv_buffer.size()) {
        
        cerr << "Received msg size error " << endl;
        clear_vec(recv_buffer);
        EVP_PKEY_free(srv_pubK);
        return false;
    }

    //get server ECDH key
    ECDH_server_key.insert(ECDH_server_key.begin(), 
                        recv_buffer.begin() + start_index,
                        recv_buffer.begin() + start_index + ECDH_key_size);

    start_index += ECDH_key_size;

    // retrieve digital signature
    dig_sign_len = recv_buffer.size() - start_index;
    if (dig_sign_len <= 0) {
        cerr << "Dig_sign length error " << endl;
        clear_vec(recv_buffer);
        clear_vec(ECDH_server_key);
        EVP_PKEY_free(srv_pubK);
        return false;
    }

    server_signature.insert(server_signature.begin(), 
                        recv_buffer.begin() + start_index, 
                        recv_buffer.end());
    start_index += dig_sign_len;

    if (payload_size > 0 && uint32_t(payload_size) != start_index - NUMERIC_FIELD_SIZE) {
        cerr << "Received data size error" << endl;
        clear_vec(server_signature);
        clear_vec(ECDH_server_key);
        clear_vec(recv_buffer);
        EVP_PKEY_free(srv_pubK);
        return false;
    }
    
    /* verify digital signature: | nonce_client | server ECDH key | */
    if (ECDH_key_size > UINT32_MAX - uint32_t(NONCE_SIZE)) {
        cerr << "receiveCertSign -> size overflow " << endl;
        clear_vec(server_signature);
        clear_vec(ECDH_server_key);
        clear_vec(recv_buffer);
        EVP_PKEY_free(srv_pubK);
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

    if (!verified) {
        cerr << "Digital Signature not verified" << endl;

        // clear buffer key
        clear_vec(ECDH_server_key);
        EVP_PKEY_free(srv_pubK);

        return false;
    }
    cout << " Digital Signature Verified!" << endl;
    
    if (active_session->deserializePubKey(ECDH_server_key.data(), ECDH_key_size, active_session->ECDH_peerKey) != 1) {
        cerr << "Error: deserializePubKey failed!" << endl;
        
        clear_vec(ECDH_server_key);
        EVP_PKEY_free(srv_pubK);
        return false;
    }

    clear_vec(ECDH_server_key);
    EVP_PKEY_free(srv_pubK);
    return true;
}

/**
 * send client digital signature
 * @srv_nonce: vector containing the nonce sent by the server, to re-send to the server
 * @priv_k: client private key needed to sign the message
 * @return: 1 on success, 0 or -1 on error (return of sendMsg())
*/
int Client::sendSign(vector<unsigned char> &srv_nonce, EVP_PKEY *&priv_k) {
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

    if (ECDH_my_key_size < 0) {
        cerr << "Error: serializePubKey failed " << endl;
        free(ECDH_my_pub_key);
        return -1;
    }

    msg_to_sign.resize(ECDH_my_key_size);
    msg_to_sign.insert(msg_to_sign.begin(), srv_nonce.begin(), srv_nonce.end());
    memcpy(msg_to_sign.data() + NONCE_SIZE, ECDH_my_pub_key, ECDH_my_key_size);
    
    signed_msg_len = active_session->signMsg(msg_to_sign.data(), NONCE_SIZE + ECDH_my_key_size, priv_k, signed_msg.data());

    if (signed_msg_len < 0) {
        cerr << "signMsg failed" << endl;
        free(ECDH_my_pub_key);
        clear_vec(msg_to_sign);
        clear_vec(signed_msg);
        return -1;
    }

    if (uint64_t(signed_msg_len) > uint64_t(UINT32_MAX - OPCODE_SIZE - uint32_t(NONCE_SIZE) -
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
    start_index += NONCE_SIZE;

    ECDH_my_key_size_n = htonl(ECDH_my_key_size);
    memcpy(send_buffer.data() + start_index, &ECDH_my_key_size_n, NUMERIC_FIELD_SIZE);  
    start_index += NUMERIC_FIELD_SIZE;

    memcpy(send_buffer.data() + start_index, ECDH_my_pub_key, ECDH_my_key_size);
    start_index += ECDH_my_key_size;

    send_buffer.insert(send_buffer.end(), signed_msg.begin(), signed_msg.end());

    // send msg to server
    ret = sendMsg(payload_size);

    // clear buffers      
    free(ECDH_my_pub_key);
    clear_vec(msg_to_sign);
    clear_vec(signed_msg);

    return ret;
}


/********************************************************************/

bool Client::buildStore(X509*& ca_cert, X509_CRL*& crl, X509_STORE*& store) {
    // load CA certificate
    string ca_cert_filename = "./client/FoundationOfCybersecurity_cert.pem";
    FILE* ca_cert_file = fopen(ca_cert_filename.c_str(), "r");
    if (!ca_cert_file) {
        cerr << "CA_cert file does not exists" << endl;
        return false;
    }
    
    ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);

    if (!ca_cert) {
       cerr << "PEM_read_X509 returned NULL" << endl;
       return false;
    }
    // load the CRL
    string crl_filename = "./client/FoundationOfCybersecurity_crl.pem";
    FILE* crl_file = fopen(crl_filename.c_str(), "r");
    if (!crl_file) {
        cerr << "CRL file not found" << endl;
        return false;
    }
    crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);

    if (!crl) {
        cerr << "PEM_read_X509_CRL returned NULL " << endl;
        return false;
    }
    // build a store with CA_cert and the CRL
    store = X509_STORE_new();
    if (!store) {
        cerr << "X509_STORE_new returned NULL\n" 
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        return false;
    }
    if (X509_STORE_add_cert(store, ca_cert) != 1) {
        cerr << "X509_STORE_add_cert error\n"
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        return false;
    }
    if (X509_STORE_add_crl(store, crl) != 1) {
        cerr << "X509_STORE_add_crl error\n" 
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        return false;
    }
    if (X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1) {
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
    if (!certToCheck) {
        cerr << "d2i_X509 failed" << endl;
        return false;
    }

    if (!buildStore(CA_cert, CA_crl, store)) {
        cerr << "buildStore failed" << endl;

        X509_free(certToCheck);

        X509_free(CA_cert);
        X509_CRL_free(CA_crl);
        X509_STORE_free(store); // deallocates also CA_cert and CRL
    }


    // verify peer's certificate
    certvfy_ctx = X509_STORE_CTX_new();
    if (!certvfy_ctx) {
        cerr << "X509_STORE_CTX_new returned NULL\n"
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        X509_free(certToCheck);

        X509_free(CA_cert);
        X509_CRL_free(CA_crl);
        X509_STORE_free(store);
        
        X509_STORE_CTX_free(certvfy_ctx);

        return false;
    }

    if (X509_STORE_CTX_init(certvfy_ctx, store, certToCheck, NULL) != 1) {
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

    if (verified) {        
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
    X509_free(CA_cert);
    X509_CRL_free(CA_crl);

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
    int ret = 1;

    if (command.compare("!help") == 0) {
        showCommands();
        
    } else if (command.compare("!list") == 0) {
        // opcode 8
        cout << "FileList operation requested" << endl;
        ret = requestFileList();
    } else if (command.compare("!upload") == 0) {
        // opcode 5
        cout << "Upload operation requested" << endl;
        ret = uploadFile();    // username saved in class member
    } else if (command.compare("!download") == 0) {
        // opcode 6
        cout << "Download operation requested" << endl;
        ret = downloadFile();
    } else if (command.compare("!rename") == 0) {
        // opcode 3
        cout << "Rename operation requested " << endl;
        ret = renameFile();    // username saved in class member
    } else if (command.compare("!delete") == 0) {
        // opcode 4
        cout << "Delete operation requested" << endl;
        ret = deleteFile();
    } else if (command.compare("!exit") == 0) {
        // logout from server - opcode 10
        cout << "Logout requested" << endl; 
        logout();    
        return false;    
    } else {
        cout << "Invalid command\nRetry" << endl;
        showCommands();
    }
    return ret == 1;
}

int Client::requestFileList() {
    string msg = username;
    uint32_t payload_size, payload_size_n;
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext;
    array<unsigned char, MAX_BUF_SIZE> output;

    cout << "****************************************" << endl;
    cout << "******     Request File List      ******" << endl;
    cout << "****************************************" << endl;


    plaintext.insert(plaintext.begin(), msg.begin(), msg.end());

    active_session->createAAD(aad.data(), FILE_LIST_REQ);
    payload_size = active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    clear_vec(plaintext);
    aad.fill('0');
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        output.fill('0');
        return -1;
    }
    payload_size_n = htonl(payload_size);
        
    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), 
                        output.begin() + payload_size);

    output.fill('0');

    if (sendMsg(payload_size) != 1) {
        cerr << "Error during send phase (C->S | File List Request)" << endl;
        clear_vec(send_buffer);
        return -1;
    }

    clear_vec(send_buffer);

    int ret = receiveFileList();
    if (ret != 1) {
        cerr << "Receive file list failed" << endl;
        return -1;
    }

    cout << "****************************************" << endl;
    cout << "*****     File List Received       *****" << endl;
    cout << "****************************************" << endl;

    return 1;
}

int Client::receiveFileList() {
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(MAX_BUF_SIZE);
    long received_len;
    uint32_t pt_len;
    uint16_t opcode;
    string filelist = "";

    while (true) {
        received_len = receiveMsg();
        if (received_len <= 0 || (received_len > 0 && uint32_t(received_len) < MIN_LEN)) {
            cerr << "Error! Exiting receive file list phase" << endl;
            clear_vec(recv_buffer);
            return -1;
        }

        pt_len = active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
        clear_vec(recv_buffer);

        if (pt_len == 0) {
            cerr << " Error during decryption" << endl;
            clear_vec(plaintext);
            aad.fill('0');
            return -1;
        }

        opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
        aad.fill('0');

        if (opcode == FILE_LIST) {
            cout << endl << string(plaintext.begin(), plaintext.end());
        } else if (opcode == END_OP) {
            cout << endl << string(plaintext.begin(), plaintext.begin() + (pt_len)) << endl;
            break;
        } else {
            cerr << "Error! The received msg was malformed" << endl;
            clear_vec(plaintext);
            return -1;
        }

        clear_vec(plaintext);
    }
    return 1;
}

void Client::logout() {
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(FILE_SIZE_FIELD);
    array<unsigned char, MAX_BUF_SIZE> output;
    uint32_t payload_size, payload_size_n;
    string msg = CLIENT_LOGOUT;

    cout << "****************************************" << endl;
    cout << "******       Client Logout        ******" << endl;
    cout << "****************************************" << endl;

    plaintext.insert(plaintext.begin(), msg.begin(), msg.end());
    active_session->createAAD(aad.data(), LOGOUT);

    payload_size = active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    clear_vec(plaintext);
    aad.fill('0');

    if (payload_size == 0) {
        cerr<<"Error! The received file list chunk was malformed"<<endl;
        output.fill('0');
        exit(EXIT_FAILURE);
    }
    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);
    output.fill('0');

    if (sendMsg(payload_size) != 1) {
        cerr<<"Error during logout phase!"<<endl;
        clear_vec(send_buffer);
        exit(EXIT_FAILURE);
    }
    clear_vec(send_buffer);

    long received_len;
    int pt_len;
    uint16_t opcode;

    received_len = receiveMsg();
    if (received_len <= 0) {
        cerr << "Error on the receiveMsg -> closing connection..." << endl;
        exit(EXIT_FAILURE);
    }
    if (uint32_t(received_len) >= MIN_LEN) {
        pt_len = active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
        clear_vec(recv_buffer);
        if (pt_len != 0) {
            opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
            aad.fill('0');
            if (opcode == END_OP) {
                cout << string(plaintext.begin(), plaintext.begin() + pt_len) << endl;
            } else {
                cerr << "Error! Unexpected message" << endl;
                clear_vec(plaintext);
                exit(EXIT_FAILURE);
            }

            clear_vec(plaintext);
        } else {
            cerr << "Error during decryption" << endl;
            aad.fill('0');
            clear_vec(plaintext);
            clear_vec(recv_buffer);
            exit(EXIT_FAILURE);
        }
    } else {
        clear_vec(recv_buffer);
        cerr << "Error during receive phase (S->C, logout)" << endl;
        exit(EXIT_FAILURE);
    }
    cout << "****************************************" << endl;
    cout << "******    Client Disconnected     ******" << endl;
    cout << "****************************************" << endl;
}

uint32_t Client::sendMsgChunks(string canon_path) {
    FILE* file = fopen(canon_path.c_str(), "rb");
    struct stat buf;

    if (!file) {
        cerr << "Error during file opening. " << endl;
        return -1;
    }

    if (stat(canon_path.c_str(), &buf) != 0) {
        cerr << "The requested file doesn't exist in " + username + "folder" << endl;
        return -1;
    }

    uint32_t tot_chunks = ceil((float)buf.st_size / FRAGM_SIZE);    //total number of chunks needed form the upload
    size_t ret, to_send;                                            //number of byte to send in the specific msg
    uint32_t payload_size, payload_size_n;
    array<unsigned char, AAD_LEN> aad;
    array<unsigned char, FRAGM_SIZE> frag_buffer;   //msg to be encrypted
    array<unsigned char, MAX_BUF_SIZE> output;      //encrypted text

    for (uint32_t i = 0; i < tot_chunks; i++) {
        //cout << "Chunk n: " << i + 1 << " of " << tot_chunks << endl;
        if (i == tot_chunks - 1) {
            to_send = buf.st_size - i * FRAGM_SIZE;
            active_session->createAAD(aad.data(), END_OP);                        //last chunk -> END_OP opcode sent to server
        } else {
            to_send = FRAGM_SIZE;
            active_session->createAAD(aad.data(), UPLOAD);                        //intermediate chunks
        }

        ret = fread(frag_buffer.data(), sizeof(char), to_send, file);

        if (ferror(file) != 0 || ret != to_send) {
            cerr << "ERROR while reading file" << endl;
            return -1;
        }

        payload_size = active_session->encryptMsg(frag_buffer.data(), to_send, aad.data(), output.data());
        aad.fill('0');
        frag_buffer.fill('0');

        if (payload_size == 0) {
            cerr << " Error during encryption. Send msg chunk phase" << endl;
            output.fill('0');
            return -1;
        }

        clear_vec(send_buffer);
        send_buffer.resize(NUMERIC_FIELD_SIZE);

        payload_size_n = htonl(payload_size);
        memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
        send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), 
                                output.begin() + payload_size);
        
        output.fill('0');
        //cout << "\t -> " << payload_size <<endl;
        if (sendMsg(payload_size) != 1) {
            cerr << "Error during send phase (C->S) | Upload Chunk Phase (chunk num: " <<i<< ")" << endl;
            clear_vec(send_buffer);
            return -1;
        }
        clear_vec(send_buffer);
        
        if(tot_chunks == 1)
            cout << "Start |==========| Finish" << endl;
        else if(i == (tot_chunks - 1)){
            for (int j = 0; (j < 10 - (int)tot_chunks) && (tot_chunks >= 10); j++)
                cout << "=";

            cout << "=| Finish" << endl;
        }
        else if(i == 0)
            cout << "Start |=" << std::flush;
        else if(i % (int)(tot_chunks/10) == 0)
            cout << "=" << std::flush;
    }

    fclose(file);
    return 1;
}



int Client::uploadFile() {
    long file_dim;
    uint32_t payload_size, payload_size_n;    
    uint32_t file_dim_l_n, file_dim_h_n; 
    string filename, file_path; 
    char* canon_file;
    array<unsigned char, AAD_LEN> aad; 
    vector<unsigned char> plaintext(FILE_SIZE_FIELD); 
    array<unsigned char, MAX_BUF_SIZE> output;

    cout << "****************************************" << endl;
    cout << "*********     UPLOAD FILE      *********" << endl;
    cout << "****************************************" << endl;

    readFilenameInput(filename, "Insert filename: ");    
    file_path = FILE_PATH_CLT + username + "/" + filename;
    canon_file = canonicalizationPath(file_path);
    if (!canon_file) {
        cerr << "File not found. Upload operation rejected." << endl;
        free(canon_file);
        return 1;
    }
    file_dim = getFileSize(canon_file);

    if (file_dim < 0 && file_dim != -1 && file_dim != -2) {
        free(canon_file);

        if (file_dim == -2)
            cerr << "File is too big! Upload terminated ---- " << file_dim << endl;
        else if  (file_dim == -1)
            cerr << "File not found! Upload not possible" << endl;
        else
            cerr << "Error on getFileSize" << endl;

        return -1;
    }             

    file_dim_h_n = htonl((uint32_t) (file_dim >> 32));
    file_dim_l_n = htonl((uint32_t) (file_dim));
    memcpy(plaintext.data(), &file_dim_l_n, NUMERIC_FIELD_SIZE);
    memcpy(plaintext.data() + NUMERIC_FIELD_SIZE, &file_dim_h_n, NUMERIC_FIELD_SIZE);
    plaintext.insert(plaintext.begin() + FILE_SIZE_FIELD, filename.begin(), filename.end());  

    active_session->createAAD(aad.data(), UPLOAD_REQ);                

    //send the basic information of the upload operation
    //to be sent: payload_size | IV | count_cs | opcode | {output}_Kcs | TAG

    payload_size = active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    clear_vec(plaintext);
    aad.fill('0');
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        output.fill('0');
        free(canon_file);
        return -1;
    }

    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);
    
    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);
    output.fill('0');

    if (sendMsg(payload_size) != 1) {
        cerr << "Error during send phase (C->S | Upload Request Phase)" << endl;
        clear_vec(send_buffer);
        free(canon_file);
        return -1;
    }

    int pt_len;                                                          
    uint16_t opcode;
    uint32_t ret;  
    long received_len;
    string server_response;

    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if (received_len <= 0 ||
        (received_len > 0 && uint32_t(received_len) < MIN_LEN)) {
        cerr << "Error during receive phase (S->C, upload)" << endl;
        clear_vec(recv_buffer);
        free(canon_file);
        return -1;
    }

    pt_len = active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
    clear_vec(recv_buffer);
    if (pt_len == 0) {
        cerr << " Error during decryption" << endl;
        clear_vec(plaintext);
        aad.fill('0');
        free(canon_file);
        return -1;
    }

    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
    aad.fill('0');
    if (opcode != UPLOAD) {
        cerr << "Error! Exiting upload request phase" << endl;
        clear_vec(plaintext);
        free(canon_file);
        return -1;
    }
    
    server_response = ((char*)plaintext.data());
    clear_vec(plaintext);
    if (server_response == FILE_FOUND) {      
        cout << "File not accepted. " << server_response << endl;
        free(canon_file);
        return 1;
    }
    if (server_response == MALFORMED_FILENAME) {
        cerr << "File not accepted. " << server_response << endl;
        free(canon_file);
        return -1;
    }
   
    cout << "*****           UPLOADING          *****" << endl;
    
    clear_vec(send_buffer);

    ret = sendMsgChunks(canon_file);
    
    free(canon_file);

    if (ret == 1) {
        plaintext.resize(MAX_BUF_SIZE);        
        received_len = receiveMsg();

        if (received_len <= 0 ||
            (received_len > 0 && uint32_t(received_len) < MIN_LEN)) {
        cerr << "Error during receive phase (S->C)" << endl;
        clear_vec(recv_buffer);
        return -1;
        }
        
        pt_len = active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
        clear_vec(recv_buffer);
        if (pt_len == 0) {
            cerr << " Error during decryption" << endl;
            clear_vec(plaintext);
            aad.fill('0');
            return -1;
        }
        opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
        aad.fill('0');
        if (opcode != END_OP) {
            cerr << "Error! Exiting upload phase." << endl;
            clear_vec(plaintext);
            return -1;
        }

        server_response = string(plaintext.begin(), plaintext.begin() + pt_len);
        clear_vec(plaintext);
        if (server_response != OP_TERMINATED) {
            cerr << "Upload not correcty terminated. " << server_response << endl;
            return -1;
        }
    } else {
        cerr << "Error! Exiting upload phase" << endl;
        return -1;
    }

    cout << "****************************************" << endl;
    cout << "*****       UPLOAD TERMINATED      *****" << endl;
    cout << "****************************************" << endl;

    return 1;
}


int Client::renameFile() {

    string old_filename, new_filename;
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(2 * NUMERIC_FIELD_SIZE);
    array<unsigned char, MAX_BUF_SIZE> output;
    uint32_t old_filename_lenght, old_filename_lenght_n;
    uint32_t new_filename_lenght, new_filename_lenght_n;
    uint32_t payload_size, payload_size_n;

    cout << "****************************************" << endl;
    cout << "*********     Rename File      *********" << endl;
    cout << "****************************************" << endl;

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

    active_session->createAAD(aad.data(), RENAME_REQ);
    payload_size = active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    
    clear_vec(plaintext);
    aad.fill('0'); 

    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        output.fill('0');
        return -1;
    }
    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    output.fill('0');

    if (sendMsg(payload_size) != 1) {
        cerr << "Error during send phase (C->S | Rename Request Phase)" << endl;
        clear_vec(send_buffer);
        return -1;
    }

    clear_vec(send_buffer);

    uint16_t opcode;
    long received_len;
    int pt_len;
    string server_response;

    received_len = receiveMsg();
    if (received_len <= 0 ||
        (received_len > 0 && uint32_t(received_len) < MIN_LEN)) {
        cerr << "Error during receive phase (S->C, rename)";
        clear_vec(recv_buffer);
        return -1;
    }

    plaintext.resize(MAX_BUF_SIZE);
    pt_len = active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
    clear_vec(recv_buffer);
    if (pt_len == 0) {
        cerr << "Error during decryption" << endl;
        clear_vec(plaintext);
        aad.fill('0');
        return -1;
    }

    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
    aad.fill('0');
    if (opcode != END_OP) {
        cerr << "Error! Exiting rename request phase" << endl;
        clear_vec(plaintext);
        return -1;
    }

    server_response = ((char*)plaintext.data());
    clear_vec(plaintext);
    if (server_response != MESSAGE_OK) {
        cout << "Rename not accepted" << server_response << endl;
    } else {
        cout << "Rename successfully completed" << endl;
    }

    cout << "****************************************" << endl;
    cout << "******     Rename Terminated      ******" << endl;
    cout << "****************************************" << endl;

    return 1;
}


//---------------------------------------------//

int Client::receiveMsgChunks( uint32_t filedimension, string canon_path) {
    ofstream outfile(canon_path, ofstream::binary);

    array<unsigned char, AAD_LEN> aad;
    array<unsigned char, MAX_BUF_SIZE> plaintext;

    long received_len;
    uint32_t opcode, pt_len;

    uint32_t tot_chunks = ceil((float)filedimension / FRAGM_SIZE);

    for (uint32_t i = 0; i < tot_chunks; i++) {

        received_len = receiveMsg();

        if (received_len <= 0) {
            cerr << "Error! Exiting receive phase" << endl;
            clear_vec(recv_buffer);
            return -1;
        }
        pt_len = active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), plaintext.data());
        clear_vec(recv_buffer);
        
        if (pt_len == 0) {
            cerr << " Error during decryption" << endl;
            plaintext.fill('0');
            aad.fill('0');
            return -1;
        }

        opcode = ntohs(*(uint32_t*)(aad.data() + NUMERIC_FIELD_SIZE));
        aad.fill('0');
        
        if ((opcode == DOWNLOAD_REQ && i == tot_chunks - 1) || (opcode == END_OP && i != tot_chunks - 1)) {
            outfile.close();
            cerr << "Wrong message format. Exiting" << endl;
            plaintext.fill('0');
            
            if (remove(canon_path.c_str()) != 0) {
                cerr << "File not correctly cancelled" << endl;
            }
            return -1;
        }

        outfile << string(plaintext.begin(), plaintext.begin() + pt_len);
        plaintext.fill('0');
        aad.fill('0');
        outfile.flush();
     
        if(tot_chunks == 1)
            cout << "Start |==========| Finish" << endl;
        else if(i == (tot_chunks - 1)){
            for (int j = 0; (j < 10 - (int)tot_chunks) && (tot_chunks >= 10); j++)
                cout << "=";

            cout << "=| Finish" << endl;
        }
        else if(i == 0)
            cout << "Start |=" << std::flush;
        else if(i % (int)(tot_chunks/10) == 0)
            cout << "=" << std::flush;
    }
    aad.fill('0');
    plaintext.fill('0');
    outfile.close();
    return 1;
}

int Client::downloadFile()
{
    string filename, file_path;
    uint32_t filename_size, filename_size_n, payload_size, payload_size_n, filedimension;   
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(NUMERIC_FIELD_SIZE);
    array<unsigned char, MAX_BUF_SIZE> ciphertext;

    readFilenameInput(filename, "Insert the name of the file you want to Download: ");
    file_path = FILE_PATH_CLT + username + "/" + filename;

    // === Checking and managing the existence of the file within the Download folder ===
    if (getFileSize(file_path) >= 0) {
        string choice;

        cout << "The requeste file already exists in the Download folder, "
                << "overwrite it?: [y/n] " << endl;
        getline(cin, choice);

        if (!cin) {
            cerr << "\n === Error during input ===\n" << endl;
            return -1;
        }

        while (choice != "Y" && choice!= "y" && choice != "N" && choice!= "n" ) {
            cout << "\nError: Type Y/y or N/n!" << endl << "Try again: [y/n] ";
            getline(cin, choice);

            if (!cin) {
                cerr << "\n === Error during input ===\n" << endl;
                return -1;
            }
        }
        if (choice == "N" || choice == "n") {
            cout << "\n\t~ The file <" << filename << ">  will not be overwritten. ~\n\n" << endl;
            return 1;
        }

        if (removeFile(file_path) != 1) {
            cerr << "\n\t --- Error during Deleting file ---\n" << endl;
            return -1; 
        }
    }
    
    // === Preparing Data Sending and Encryption ===
    filename_size = filename.size();
    filename_size_n = htonl(filename_size);
    memcpy(plaintext.data(), &filename_size_n, NUMERIC_FIELD_SIZE);
    plaintext.insert(plaintext.begin() + NUMERIC_FIELD_SIZE, filename.begin(), filename.begin() + filename.size());

    active_session->createAAD(aad.data(), DOWNLOAD_REQ);
    
    payload_size = active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                                    aad.data(), ciphertext.data());
    clear_vec(plaintext);
    aad.fill('0');
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        ciphertext.fill('0');
        return -1;
    }

    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);

    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, ciphertext.begin(),
                        ciphertext.begin() + payload_size);
    ciphertext.fill('0');


// _BEGIN_(1)-------------- [ M1: INVIO_RICHIESTA_DOWNLOAD_AL_SERVER ] --------------

    if (sendMsg(payload_size) != 1) {
        cerr << "Error during send phase (C->S)" << endl;
        clear_vec(send_buffer);
        return -1;
    }

// _END_(1))-------------- [ M1: INVIO_RICHIESTA_DOWNLOAD_AL_SERVER ] --------------  

    uint16_t opcode;
    uint64_t received_len;  //Legnht of the message received from the server 
    uint32_t plaintext_len;
    string server_response; //Message from the server containing the response to the request
    int fileChunk; //Management Chunk

    received_len = receiveMsg();
    if (received_len <= 0) {
        cerr << "Error during receive phase (S->C)" << endl;
        clear_vec(recv_buffer);
        return -1;
    }

    //received from server in terms of byte
    plaintext.resize(MAX_BUF_SIZE);
    plaintext_len = active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), plaintext.data());
    clear_vec(recv_buffer);
    if (plaintext_len == 0) {
        cerr << " Error during decryption" << endl;
        aad.fill('0');
        clear_vec(plaintext);
        return -1;
    }
    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));   
    aad.fill('0');
 
    if (opcode != DOWNLOAD) {
        cerr << "Error! Exiting download request phase" << endl;
        clear_vec(plaintext);
        return -1;
    }

// _BEGIN_(2)------ [M2: RICEZIONE_CONFERMA_RICHIESTA_DOWNLOAD_DAL_SERVER ] ------
    
    /*--- Check Response file existence in the Cloud Storage by the Server ---*/
    filedimension = ntohl(*(uint32_t*)plaintext.data());
    server_response.insert(server_response.begin(), plaintext.begin() + NUMERIC_FIELD_SIZE, plaintext.begin() + plaintext_len);    
    
    clear_vec(plaintext);
    if (server_response != MESSAGE_OK) {       
        cout << "The file cannot be downloaded: " << server_response << endl;
        // the return value is 1 also in this case because the error is not a security error
        return 1;
    }
    
// _END_(2)------ [ M2: RICEZIONE_CONFERMA_RICHIESTA_DOWNLOAD_DAL_SERVER ] )------

    cout << "\nThe requested file is in the cloud storage and can be downloaded." << endl;
    cout << "\n\t ...Download file " + filename +" in progress...\n\n" << endl;    

// _BEGIN_(3)-------------- [ M3: RICEZIONE_FILE_DAL_SERVER ] --------------

    fileChunk = receiveMsgChunks(filedimension, file_path);

    if (fileChunk != 1) {
        cerr << "Error! Exiting Download phase" << endl;
        clear_vec(recv_buffer);        
        return -1;
    }

// _END_(3)-------------- [ M3: RICEZIONE_FILE_DAL_SERVER ] --------------
    
    cout << "\n\tFile Download Completed!" << endl;

    // === Preparing Data Sending and Encryption ===    
    active_session->createAAD(aad.data(), END_OP);
    string ack_msg = DOWNLOAD_TERMINATED;
    
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());

    payload_size = active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                                    aad.data(), ciphertext.data());
    clear_vec(plaintext);
    aad.fill('0');
    
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        ciphertext.fill('0');
        return -1;
    }
    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin()+ NUMERIC_FIELD_SIZE, ciphertext.begin(),
                        ciphertext.begin() + payload_size);
    ciphertext.fill('0');

// _BEGIN_(4)-------------- [ M4: INVIO_CONFERMA_DOWNLOAD_AL_SERVER ] --------------

    if (sendMsg(payload_size) != 1) {
        cerr << "Error during send phase (C->S)" << endl;
        clear_vec(send_buffer);
        return -1;
    }
    
// _END_(4)-------------- [ M4: INVIO_CONFERMA_DOWNLOAD_AL_SERVER ] --------------
    
    return 1;
}

int Client::deleteFile() {
    string filename;
    uint32_t payload_size, payload_size_n;   
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext;
    array<unsigned char, MAX_BUF_SIZE> ciphertext;

// _BEGIN_(1)-------------- [ M1: SEND_DELETE_REQUEST_TO_SERVER ] --------------

    readFilenameInput(filename, "Insert the name of the file you want to delete: ");

    // === Preparing Data Sending and Encryption  ===
    plaintext.insert(plaintext.begin(), filename.begin(), filename.end());
    active_session->createAAD(aad.data(), DELETE_REQ);
    
    payload_size = active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                                    aad.data(), ciphertext.data());
    // === Cleaning ===
    clear_vec(plaintext);
    aad.fill('0');

    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        ciphertext.fill('0');
        return -1;
    }

    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, 
                        ciphertext.begin(), ciphertext.begin() + payload_size);
    ciphertext.fill('0');

    if (sendMsg(payload_size) != 1) {
        cerr << "Error during send phase (C->S)" << endl;
        clear_vec(send_buffer);
        return -1;
    }

// _END_(1))-------------- [ M1: SEND_DELETE_REQUEST_TO_SERVER ] --------------


// _BEGIN_(2)------ [M2: RECEIVE_CONFIRMATION_DELETE_REQUEST_FROM_SERVER ] ------

    uint16_t opcode;
    long received_len;  
    uint32_t pt_len;
    string server_response, choice; 


    received_len = receiveMsg();
    if (received_len <= 0) {
        cerr << "Error during receive phase (S->C)" << endl;
        clear_vec(recv_buffer);

        return -1;
    }

    // === Reuse of vectors declared at the beginning ===
    plaintext.resize(MAX_BUF_SIZE);
    //received from server in terms of byte
    pt_len = active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), plaintext.data());
    clear_vec(recv_buffer);

    if (pt_len == 0) {
        cerr << " Error during decryption" << endl;
        clear_vec(plaintext);
        aad.fill('0');
        return -1;
    }

    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));    
    aad.fill('0');
    if (opcode != DELETE) {
        cerr << "Error! Exiting DELETE request phase" << endl;
        clear_vec(plaintext);
        return -1;
    }
    
    /*--- Check Response existence of file in the Cloud Storage by the Server ---*/
    server_response = ((char*)plaintext.data());
    clear_vec(plaintext);

    if (server_response != MESSAGE_OK) {       
        cout << "Delete request refused: " << server_response << endl;
        if (server_response == MALFORMED_FILENAME) 
            return  -1;

        return 1;
    }
    
// _END_(2)-------- [ M2: RECEIVE_CONFIRMATION_DELETE_REQUEST_FROM_SERVER ] --------
    
    cout << "Are you sure to delete the file " << filename << "?: [y/n]" << endl;
    getline(cin, choice);

    if (!cin) {
        cerr << "\n === Error during input ===\n" << endl;
        return -1;
    }

    while (choice != "Y" && choice!= "y" && choice != "N" && choice!= "n" ) {
        cout << "\nError: Type Y/y or N/n!" << endl << "Try again: [y/n] ";
        getline(cin, choice);

        if (!cin) {
            cerr << "\n === Error during input ===\n" << endl;
            return -1;
        }
    }

    if (choice == "N" || choice == "n") {
        cout << "\n\t The file '" << filename << "' will not be deleted. \n" << endl;
    }
        
    
// _BEGIN_(3)-------------- [ M3: SEND_USER-CHOICE_TO_SERVER ] --------------

    // === Preparing Data Sending and Encryption ===    
    active_session->createAAD(aad.data(), DELETE);
    
    plaintext.insert(plaintext.begin(), choice.begin(), choice.end());

    payload_size = active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                                    aad.data(), ciphertext.data());
    clear_vec(plaintext);
    aad.fill('0');
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        ciphertext.fill('0');
        return -1;
    }
    clear_vec(send_buffer);
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    payload_size_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE,
                        ciphertext.begin(), ciphertext.begin() + payload_size);
    ciphertext.fill('0');

    if (sendMsg(payload_size) != 1) {
        cerr << "Error during send phase (C->S)" << endl;
        clear_vec(send_buffer);

        return -1;
    }

    clear_vec(send_buffer);
    
// _END_(3)-------------- [ M3: SEND_USER-CHOICE_TO_SERVER] --------------


//_BEGIN_(4)---------- [M4: RECEIVE_CONFIRMATION_DELETE_OPERATION_FROM_SERVER ] ----------

    received_len = receiveMsg();
    if (received_len <= 0) {
        cerr << "Error during receive phase (S->C)" << endl;
        clear_vec(recv_buffer);            
        return -1;
    }

    // === Reuse of vectors declared at the beginning ===
    plaintext.resize(MAX_BUF_SIZE);
    //received from server in terms of byte
    pt_len = active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), plaintext.data());
    clear_vec(recv_buffer);

    if (pt_len == 0) {
        cerr << " Error during decryption" << endl;
        clear_vec(plaintext);
        aad.fill('0');
        return -1;
    }

    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
    aad.fill('0');    
    if (opcode != END_OP) {
        cerr << "Error! Exiting DELETE phase" << endl;
        clear_vec(plaintext);
        return -1;
    }
    
    server_response = ((char*)plaintext.data());
    clear_vec(plaintext);
    cout << "\nEND_DELETE_OPERATION_MSG: " << server_response << endl;

//_END_(4)----------- [ M4: RECEIVE_CONFIRMATION_DELETE_OPERATION_FROM_SERVER ] -----------

    return 1;
}