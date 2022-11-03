#include "client.h"

Client::Client(string username, string srv_ip) {
    this->username = username;
    active_session = new Session();
    /*
    send_buffer = (unsigned char*)malloc(MAX_BUF_SIZE);
    if(!send_buffer)
        handleErrors("Malloc error");
    recv_buffer = (unsigned char*)malloc(MAX_BUF_SIZE);
    if(!recv_buffer)
        handleErrors("Malloc error");
        */
    createSocket(srv_ip);
}

Client::~Client() {
    username.clear();
    if(!send_buffer.empty()) {
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
        //send_buffer.fill('0');
        //free(send_buffer);
        //send_buffer = nullptr;
    }
    if(!recv_buffer.empty()) {
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();
        //recv_buffer.fill('0');
        //free(recv_buffer);
        //recv_buffer = nullptr;
    }
}

void Client::createSocket(string srv_ip) {
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)  // socket TCP
        handleErrors("Socket creation error");
    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = htons(SRV_PORT);
    if(inet_pton(AF_INET, srv_ip.c_str(), &sv_addr.sin_addr) != 1)
        handleErrors("Server IP not valid");
    if(connect(sd, (struct sockaddr*)&sv_addr, sizeof(sv_addr)) != 0)
        handleErrors("Connection to server failed");
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
        send_buffer.clear();    //fill('0');
        return -1;
    }
    payload_size += NUMERIC_FIELD_SIZE;
    if(send(sd, send_buffer.data(), payload_size, 0) < payload_size) {
        perror("Socker error: send message failed");
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();    //fill('0');
        return -1;
    }
    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();    //fill('0');

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
    recv_buffer.clear();    //fill('0');

    msg_size = recv(sd, receiver.data(), MAX_BUF_SIZE-1, 0);
    cout << "received msg size: " << msg_size << endl;

    if (msg_size == 0) {
        cerr << "The connection has been closed" << endl;
        return 0;
    }

    if (msg_size < 0 || msg_size < (uint)NUMERIC_FIELD_SIZE + (uint)OPCODE_SIZE) {
        perror("Socket error: receive message failed");
        receiver.fill('0');
        //memset(recv_buffer, 0, MAX_BUF_SIZE);
        return -1;
    }

    payload_size = *(uint32_t*)(receiver.data());
    payload_size = ntohl(payload_size);
    cout << payload_size << " received payload length" << endl;
    //check if received all data
    if (payload_size != msg_size - (int)NUMERIC_FIELD_SIZE) {
        cerr << "Error: Data received too short (malformed message?)" << endl;
        receiver.fill('0');
        //memset(recv_buffer, 0, MAX_BUF_SIZE);
        return -1;
    }

    recv_buffer.insert(recv_buffer.begin(), receiver.begin(), receiver.begin() + msg_size);
    receiver.fill('0');     // erase content of the temporary receiver buffer

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
        cerr << "Authentication failed" << endl;
    }
    

    // M2: receive server cert e ECDH_server_key
    cout << "authentication->receiveMsg" << endl;

    // receive M2
    if(!receiveCertSign(client_nonce, server_nonce)) {
        cerr << "receiveVerifyCert failed" << endl;
        return false;
    }
    /*
    //start_index = 0;
    int received_size = receiveMsg(payload_size);    // return total size received data

    active_session->deserializeKey(ECDH_srv_key, ECDH_key_size, active_session->ECDH_peerKey);
    */
    // DONE legge/deserializza msg -> verifica nonce -> verifica cert server -> verifica firma server -> 
    //genera ECDH_key -> prepara buffer&invia -> riceve login ack
    
    active_session->retrievePrivKey("./client/users/" + username + "/" + username + "_key.pem", my_priv_key);
    active_session->generateECDHKey();
    ret = sendSign(server_nonce, my_priv_key);
    cout << "sendsign serv nonce" << endl;
    server_nonce.clear();
    if(ret != 1) {
        cerr << "sendSign failed " << endl;
        EVP_PKEY_free(my_priv_key);
        return false;
    }
    /*
    unsigned char* ECDH_my_pub_key = NULL;
    unsigned int ECDH_my_key_size = active_session->serializeKey(active_session->ECDH_myKey, ECDH_my_pub_key);
    */

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

    active_session->generateNonce(client_nonce.data());

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

    start_index = NUMERIC_FIELD_SIZE;   // reading starts after payload_size field

    // check opcode
    opcode = *(uint16_t*)(recv_buffer.data() + start_index);
    opcode = ntohs(opcode);
    start_index += OPCODE_SIZE;
    //cout << "start index " << start_index << endl;
    if(opcode != LOGIN) {
        if(opcode == ERROR) {
            //string errorMsg((const char*)recv_buffer.data() + start_index, payload_size - OPCODE_SIZE);
            string errorMsg(recv_buffer.begin() + start_index, recv_buffer.end());
            cerr << errorMsg << endl;
        } else {
            cerr << "Received not expected message" << endl;
        }
        
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();    //fill('0');

        return false;
    }
    //cout << opcode << " received opcode client" << endl;

    // retrieve & check client nonce
    received_nonce.reserve(NONCE_SIZE);
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
    // memset(nonce, 0, NONCE_SIZE);
    //free(nonce);

    // retrieve server nonce
    srv_nonce.insert(srv_nonce.begin(), 
                    recv_buffer.begin() + start_index, 
                    recv_buffer.begin() + start_index + NONCE_SIZE);
    //memcpy(srv_nonce.data(), recv_buffer.data() + start_index, NONCE_SIZE);   // server nonce
    start_index += NONCE_SIZE;

    // retrieve server cert
    cert_size = *(uint32_t*)(recv_buffer.data() + start_index);
    cert_size = ntohl(cert_size);
    start_index += NUMERIC_FIELD_SIZE;

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

    // retrieve ECDH server pub key: size + key
    ECDH_key_size = *(uint32_t*)(recv_buffer.data() + start_index);
    ECDH_key_size = ntohl(ECDH_key_size);
    start_index += NUMERIC_FIELD_SIZE;

    //get key
    ECDH_server_key.insert(ECDH_server_key.begin(), 
                        recv_buffer.begin() + start_index,
                        recv_buffer.begin() + start_index + ECDH_key_size);

    start_index += ECDH_key_size;

    // retrieve digital signature
    //int dig_sign_len = payload_size + NUMERIC_FIELD_SIZE - start_index; //*(unsigned int*)(recv_buffer + start_index);
    dig_sign_len = recv_buffer.size() - start_index;
    if(dig_sign_len <= 0) {
        cerr << "Dig_sign length error " << endl;
        //memset(ECDH_server_key.data(), '0', ECDH_server_key.size());
        ECDH_server_key.assign(ECDH_server_key.size(), '0');
        ECDH_server_key.clear();
        return false;
    }

    /*
    unsigned char *dig_sign = (unsigned char*)malloc(dig_sign_len);
    if(!dig_sign)
        handleErrors("Malloc error");
        */
    server_signature.insert(server_signature.begin(), 
                        recv_buffer.begin() + start_index, 
                        recv_buffer.end());
    //memcpy(server_dig_sign.data(), recv_buffer. + start_index, dig_sign_len);
    start_index += dig_sign_len;
    if(start_index - NUMERIC_FIELD_SIZE != payload_size) {
        cerr << "Received data size error" << endl;
        //memset(server_dig_sign.data(), '0', server_dig_sign.size());
        server_signature.assign(server_signature.size(), '0');
        //memset(ECDH_server_key.data(), '0', ECDH_server_key.size());
        ECDH_server_key.assign(ECDH_server_key.size(), '0');
        ECDH_server_key.clear();
        server_signature.clear();
        return false;
    }
    
    // verify digital signature
    signed_msg_len = NONCE_SIZE + ECDH_key_size;

    /*
    unsigned char* signed_msg = (unsigned char*)malloc(signed_msg_len);
    if(!signed_msg)
        handleErrors("Malloc error");
        */

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
    BIO_dump_fp(stdout, (const char*) ECDH_server_key.data(), ECDH_key_size);
    active_session->deserializePubKey(ECDH_server_key.data(), ECDH_key_size, active_session->ECDH_peerKey);
    return true;
}

/**
 * send client digital signature
 * @srv_nonce: vector containing the nonce sent by the server, to re-send to the server
 * @priv_k: client private key needed to sign the message
 * @return: 1 on success, 0 or -1 on error (return of sendMsg())
*/
int Client::sendSign(vector<unsigned char> &srv_nonce, EVP_PKEY *priv_k) {
    cout << "Client -> sendSign " << endl;

    int ret = 0;

    unsigned char* ECDH_my_pub_key = nullptr;
    uint32_t ECDH_my_key_size;
    uint32_t ECDH_my_key_size_n;
    
    vector<unsigned char> msg_to_sign(NONCE_SIZE + ECDH_my_key_size);
    vector<unsigned char> signed_msg(EVP_PKEY_size(priv_k));
    long signed_msg_len;

    uint32_t payload_size;
    uint32_t payload_n;
    uint16_t opcode;
    uint32_t start_index;

    ECDH_my_key_size = active_session->serializePubKey(
                                    active_session->ECDH_myKey, ECDH_my_pub_key);

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

    // prepare send buffer
    if(!send_buffer.empty()) {
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
    }
    send_buffer.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE + NONCE_SIZE +NUMERIC_FIELD_SIZE + ECDH_my_key_size);
    //memset(send_buffer, 0, MAX_BUF_SIZE);

    payload_size = OPCODE_SIZE + NONCE_SIZE + NUMERIC_FIELD_SIZE + ECDH_my_key_size + signed_msg_len;
    payload_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_n, NUMERIC_FIELD_SIZE);
    start_index = NUMERIC_FIELD_SIZE;

    opcode = htons((uint16_t)LOGIN);
    memcpy(send_buffer.data() + start_index, &opcode, OPCODE_SIZE);
    start_index += OPCODE_SIZE;

    send_buffer.insert(send_buffer.begin() + start_index, srv_nonce.begin(), srv_nonce.end());
    //memcpy(send_buffer.data() + start_index, srv_nonce.data(), NONCE_SIZE);
    start_index += NONCE_SIZE;

    ECDH_my_key_size_n = htonl(ECDH_my_key_size);
    memcpy(send_buffer.data() + start_index, &ECDH_my_key_size_n, NUMERIC_FIELD_SIZE);    
    start_index += NUMERIC_FIELD_SIZE;

    memcpy(send_buffer.data() + start_index, ECDH_my_pub_key, ECDH_my_key_size);
    start_index += ECDH_my_key_size;
    
    send_buffer.insert(send_buffer.end(), signed_msg.begin(), signed_msg.end());
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
        //handleErrors("CA_cert file doesn't exist");
        cerr << "CA_cert file does not exists" << endl;
        return false;
    }
    
    ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);

    if(!ca_cert){
       // handleErrors("PEM_read_X509 returned NULL");
       cerr << "PEM_read_X509 returned NULL" << endl;
       return false;
    }
    // load the CRL
    string crl_filename = "./client/FoundationOfCybersecurity_crl.pem";
    FILE* crl_file = fopen(crl_filename.c_str(), "r");
    if(!crl_file) {
        //handleErrors("CRL file doesn't exist");
        cerr << "CRL file not found" << endl;
        return false;
    }
    crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);

    if(!crl){
        //handleErrors("PEM_read_X509_CRL returned NULL");
        cerr << "PEM_read_X509_CRL returned NULL " << endl;
        return false;
    }
    // build a store with CA_cert and the CRL
    store = X509_STORE_new();
    if(!store) {
        cerr << "X509_STORE_new returned NULL\n" 
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        //handleErrors(err.c_str());
        return false;
    }
    if(X509_STORE_add_cert(store, ca_cert) != 1) {
        cerr << "X509_STORE_add_cert error\n"
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        //handleErrors(err.c_str());
        return false;
    }
    if(X509_STORE_add_crl(store, crl) != 1) {
        cerr << "X509_STORE_add_crl error\n" 
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        //handleErrors(err.c_str());
        return false;
    }
    if(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1) {
        cerr << "X509_STORE_set_flags error\n" 
            << ERR_error_string(ERR_get_error(), NULL) << endl;
        //handleErrors(err.c_str());
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
        //handleErrors("d2i_X509 failed");
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
        //handleErrors(err.c_str());
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
        //handleErrors(err.c_str());
        
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
    cout << "!list -> show available file list" << endl;
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
        requestFileList();
        /*
        string msg = "Available users?";
        active_session->userList((unsigned char*)msg.c_str(), msg.length());*/
        // se unsigned char msg[] => active_session->userList(msg, sizeof(msg));
    } else if(command.compare("!upload") == 0) {
        // opcode 1
        // TODO
        uploadFile();    // username saved in class member
    } else if(command.compare("!download") == 0) {
        // opcode 2
        // TODO
        downloadFile();
    } else if(command.compare("!rename") == 0) {
        // opcode 3
        // TODO
        renameFile();    // username saved in class member
    } else if(command.compare("!delete") == 0) {
        // opcode 4
        // TODO
        deleteFile();
    } else if(command.compare("!exit") == 0) {
        // logout from server - opcode 10
        // TODO
        logout();        
    } else {
        cout << "Invalid command" << endl;
        return false;
    }
    return true;
}

void Client::requestFileList() {
    cout << "client -> fileList\n";
    // opcode 2
    string msg = "Available files?";
    send_buffer.clear();    //fill('0');
    //memset(send_buffer, 0, MAX_BUF_SIZE);
    int payload_size = active_session->fileList((unsigned char*)msg.c_str(), msg.length(), send_buffer.data());    // prepare msg to send
    int ret = sendMsg(payload_size);
    if(ret != 1) {
        cerr << "send requestFileList failed" << endl;
        // todo: clear buffer
        return;
    }

    receiveFileList();
}

// TODO
void Client::receiveFileList() {
    unsigned char *aad, *user_list;
    int aad_len;
    int payload_size = receiveMsg();
    if(payload_size <= 0) {
        cerr << "Error on the receiveMsg -> closing connection..." << endl;
        return;
    }
    //int received_size = receiveMsg(payload_size);
    int list_len = active_session->decryptMsg(recv_buffer.data() + NUMERIC_FIELD_SIZE, payload_size, aad, aad_len, user_list);
    uint16_t opcode_n = *(uint16_t*)(aad + NUMERIC_FIELD_SIZE);
    uint16_t opcode = ntohs(opcode_n);
    if(opcode == ERROR) {
        string errorMsg((const char*)user_list, strlen((char*)user_list));
        cerr << errorMsg << endl;
        //handleErrors("Error opcode");
        return;
    } else if(opcode != FILE_LIST) {
        handleErrors("Opcode error, message tampered");
    }
    if(list_len != strlen((char*)user_list)) {
        cerr << "received list damaged" << endl;
        return;
    }
    string list((const char*)user_list);    // users list already formatted by the server
    cout << "Available files:\n" << list << endl;
}

// TODO
void Client::logout() {
    // deallocare tutte le risorse utilizzate e chiudere il socket di connessione col server

}

void Client::sendErrorMsg(string errorMsg) {
        //cerr << errorMsg << endl;

        // inviare mess errore al client
        int payload_size = OPCODE_SIZE + errorMsg.size();
        uint16_t op = ERROR;

        int written = 0;
        memcpy(send_buffer.data(), &payload_size, NUMERIC_FIELD_SIZE);
        written += NUMERIC_FIELD_SIZE;
        memcpy(send_buffer.data() + written, &op, OPCODE_SIZE);
        written += OPCODE_SIZE;
        memcpy(send_buffer.data() + written, errorMsg.c_str(), errorMsg.size());
        
        sendMsg(payload_size);

}

uint64_t Client::searchFile(string filename){
    string path = "./users/" + this->username +"/" + filename;
    struct stat buffer;
    if(stat(path.c_str(), &buffer) != 0){
        cerr<<"File not present"<<endl;
        return -1;
    }
    if(buffer.st_size > MAX_FILE_DIMENSION){
        cerr<<"File too big"<<endl;
        return -1;
    }
    return buffer.st_size;
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
    uint32_t payload_size;                                                              //size of the msg payload both in host and network format
    string str_payload_size_n;
    int ret;                                                                       //bytes read by the fread function
    vector<unsigned char> aad;                                                          //aad of the msg
    array<unsigned char, FRAGM_SIZE> frag_buffer;                                       //msg to be encrypted
    array<unsigned char, MAX_BUF_SIZE> output;                                          //encrypted text

    frag_buffer.fill('0');

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

        payload_size = this->active_session->encryptMsg(frag_buffer.data(), frag_buffer.size(), aad.data(), aad.size(), output.data());
        
        aad.assign(aad.size(), '0');
        aad.clear();
        frag_buffer.fill('0');

        str_payload_size_n = to_string(htonl(payload_size));

        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
        send_buffer.resize(NUMERIC_FIELD_SIZE);

        send_buffer.insert(send_buffer.begin(), str_payload_size_n.begin(), str_payload_size_n.end());
        send_buffer.insert(send_buffer.begin() + str_payload_size_n.size(), output.begin(), output.begin() + payload_size);

        output.fill('0');

        if(sendMsg(payload_size) != 1){
            cerr<<"Error during send phase (C->S) | Upload Chunk Phase (chunk num: "<<i<<")"<<endl;
            return -1;
        }
    }
}

//TODO cambia i cout di errore in cerr
int Client::uploadFile(){
    uint64_t file_dim;                                                      //dimension (in byte) of the file to upload
    uint32_t payload_size, payload_size_n;                                  //size of the msg payload both in host and network format
    uint32_t file_dim_l_n, file_dim_h_n;                                    //low and high part of the file_dim variable in network form
    string filename;                                                        //name of the file to upload
    vector<unsigned char> aad;                                              //aad of the msg
    vector<unsigned char> plaintext(FILE_SIZE_FIELD);                       //plaintext to be encrypted
    array<unsigned char, MAX_BUF_SIZE> output;                              //encrypted text

    cout<<"****************************************"<<endl;
    cout<<"*********     UPLOAD FILE      *********"<<endl;
    cout<<"****************************************"<<endl<<endl;

    readFilenameInput(filename);
    file_dim = searchFile(filename);

    if(file_dim >= MAX_FILE_DIMENSION){
        cout << "File is too big! Upload terminated"<<endl;
        return -1;
    }                      

    //insert in the plaintext filedimension and filename
    file_dim_h_n = htonl((uint32_t) (file_dim >> 32));
    file_dim_l_n = htonl((uint32_t) (file_dim));
    memcpy(plaintext.data(), &file_dim_h_n, NUMERIC_FIELD_SIZE);
    memcpy(plaintext.data() + NUMERIC_FIELD_SIZE, &file_dim_l_n, NUMERIC_FIELD_SIZE);
    plaintext.insert(plaintext.begin() + FILE_SIZE_FIELD, filename.begin(), filename.end());  

    this->active_session->createAAD(aad.data(), UPLOAD_REQ);                

    //send the basic information of the upload operation
    //to be sent: payload_size | IV | count_cs | opcode | {output}_Kcs | TAG

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), aad.size(), output.data());
    payload_size_n = htonl(payload_size);

    aad.assign(aad.size(), '0');
    aad.clear();
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();    
    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    if(sendMsg(payload_size) != 1){
        cout<<"Error during send phase (C->S | Upload Request Phase)"<<endl;
        return -1;
    }

    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();
    send_buffer.resize(NUMERIC_FIELD_SIZE);
    output.fill('0');

    //receive from the server the response to the upload request
    //received_len:  legnht of the message received from the server
    //server_response: message from the server containing the response to the request
    int aad_len, pt_len;                                                          
    uint16_t opcode;
    uint32_t ret;  
    uint64_t received_len;
    string server_response;

    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len == 0 || received_len == -1){
        cerr<<"Error during receive phase (S->C)"<<endl;
        return -1;
    }

    pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), aad_len, plaintext.data());
    
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

    aad.assign(aad.size(), '0');
    aad.clear();
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();

    ret = sendMsgChunks(filename);

    if(ret != -1){
        //TODO: receive server response to check if file was saved
        pt_len = this->active_session->decryptMsg(recv_buffer.data(), received_len, aad.data(), aad_len, plaintext.data());
        opcode = ntohs(*(uint16_t*)(aad.data() + sizeof(uint32_t)));
        if(opcode != END_OP){
            cerr<<"Error! Exiting upload phase"<<endl;
            return -1;
        }
        if(server_response != UPLOAD_TERMINATED){
            cerr<<"Upload not correcty terminated. "<<server_response<<endl;
            return -1;
        }
    }
    cout<<"        ---- UPLOAD TERMINATED ----"<<endl<<endl;

    if(ret == -1){
        cerr<<"Error! Exiting upload phase"<<endl;
        return -1;
    }

    cout<<"****************************************"<<endl<<endl;
}

void Client::downloadFile(){}

void Client::renameFile(){
    string old_filename, new_filename;
    cout<<"****************************************"<<endl;
    cout<<"*********     Rename File      *********"<<endl;
    cout<<"****************************************"<<endl;

    readInput(old_filename, MAX_NAME_SIZE, "Insert the name of the file to be changed");
    readInput(new_filename, MAX_NAME_SIZE, "Insert the new name of the file ");

    //send the information of the rename operation
    //to be sent: <count_cs, opcode=3, {old_filename, new_filename}_Kcs>

    //server response: <count_sc, op_code=3, {ResponseMsg}_Kcs>
}

void Client::deleteFile(){}