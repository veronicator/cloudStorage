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
int Client::sendMsg(int payload_size) {
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

    uint32_t payload_n = *(uint32_t*)(receiver.data());
    uint32_t payload_size = ntohl(payload_n);
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
    
    array<unsigned char, NONCE_SIZE> client_nonce;
    vector<unsigned char> server_nonce(NONCE_SIZE);

    // M1
    if(sendUsername(client_nonce) != 1) {
        cerr << "Authentication failed" << endl;
    }
    
    /*
    int start_index = 0;
    uint32_t payload_size = OPCODE_SIZE + NONCE_SIZE + username.size();

    memset(send_buffer, 0, MAX_BUF_SIZE);
    active_session->generateNonce();
    // prepare buffer: | payload_size | opcode | nonce_client | username |
    uint32_t payload_n = htonl(payload_size);
    memcpy(send_buffer, (unsigned char*)&payload_n, NUMERIC_FIELD_SIZE);
    start_index += NUMERIC_FIELD_SIZE;
    uint16_t opcode = htons((uint16_t)LOGIN);
    memcpy(send_buffer + start_index, (unsigned char*)&opcode, OPCODE_SIZE);
    start_index += OPCODE_SIZE;
    memcpy(send_buffer + start_index, active_session->nonce.data(), NONCE_SIZE);
    start_index += NONCE_SIZE;
    memcpy(send_buffer + start_index, username.c_str(), username.size());
    start_index += username.size();
    //sendMsg
    cout << "authentication->sendMsg (nonce, usr)" << endl;
    sendMsg(payload_size);     // dimensione del messaggio da inviare -> solo payload, l'header viene aggiunto in sendMsg
    */
    /*BIO_dump_fp(stdout, (const char*)send_buffer, start_index);    // stampa in esadecimale
    cout << payload_size << " buffer len" << strlen((char*)send_buffer) << endl;
    for(int i=0; i<start_index; i++) {
        cout << send_buffer[i];
    }
    cout << endl;*/

    // M2: receive server cert e ECDH_server_key
    cout << "authentication->receiveMsg" << endl;
    vector<unsigned char> server_nonce(NONCE_SIZE);
    /*unsigned char* srv_nonce = (unsigned char*)malloc(NONCE_SIZE);
    if(!srv_nonce) {
        cerr << "Malloc failed " << endl;
        
        return false;
    }
    */
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
    
    EVP_PKEY *my_priv_key;
    active_session->retrievePrivKey("./client/users/" + username + "/" + username + "_key.pem", my_priv_key);
    active_session->generateECDHKey();
    sendSign(server_nonce, my_priv_key);
    cout << "sendsign serv nonce" << endl;
    server_nonce.clear();
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
    int start_index = 0;
    uint32_t payload_size = OPCODE_SIZE + NONCE_SIZE + username.size();
    uint32_t payload_n = htonl(payload_size);

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

    uint16_t opcode = htons((uint16_t)LOGIN);
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
bool Client::receiveCertSign(array<unsigned char, NONCE_SIZE> client_nonce, 
                            vector<unsigned char> &srv_nonce) {
    cout << "receiveCertSign\n";

    int start_index = 0;
    int payload_size =  receiveMsg();

    start_index = NUMERIC_FIELD_SIZE;   // reading starts after payload_size field

    // check opcode
    uint16_t opcode_n = *(uint16_t*)(recv_buffer.data() + start_index);
    uint16_t opcode = ntohs(opcode_n);
    start_index += OPCODE_SIZE;
    cout << "start index " << start_index << endl;
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
        /*
        #pragma optimize("", off);
            memset(recv_buffer, 0, MAX_BUF_SIZE);
        #pragma optimize("", on);
        
        free(recv_buffer);
        free(srv_nonce);
        */

        return false;
    }
    //cout << opcode << " received opcode client" << endl;

    // retrieve & check client nonce
    vector<unsigned char> received_nonce;
    received_nonce.reserve(NONCE_SIZE);
    received_nonce.insert(received_nonce.begin(), 
                        recv_buffer.begin() + start_index, 
                        recv_buffer.begin() + start_index + NONCE_SIZE);
    //memcpy(received_nonce.data(), recv_buffer.data() + start_index, NONCE_SIZE);
    /*
    unsigned char *nonce = (unsigned char*)malloc(NONCE_SIZE);
    if(!nonce) {
        cerr << "Malloc nonce failed" << endl;
        //fare funzione che svuota i vari buffer usati, per evitare troppa ridondanza
        return false;
    }
    */

    //memcpy(received_nonce.data(), recv_buffer.data() + start_index, NONCE_SIZE);   // client nonce
    start_index += NONCE_SIZE;
    if(!active_session->checkNonce(received_nonce.data(), client_nonce.data())) {
        cerr << "Received nonce not valid\n";
        received_nonce.clear();
        client_nonce.fill('0');
        // deallocare tutti i buffer utilizzati
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();    //fill('0');
        /*
        #pragma optimize("", off);
            memset(recv_buffer, 0, MAX_BUF_SIZE);
        #pragma optimize("", on);
        
        //free(nonce);
        free(recv_buffer);
        //free(srv_nonce);
        */
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
    uint32_t cert_size_n = *(uint32_t*)(recv_buffer.data() + start_index);
    int cert_size = ntohl(cert_size_n);
    start_index += NUMERIC_FIELD_SIZE;

    // get server certificate
    vector<unsigned char> buffer;
    buffer.insert(buffer.begin(), 
                recv_buffer.begin() + start_index, 
                recv_buffer.begin() + start_index + cert_size);
    
    //array<unsigned char, MAX_BUF_SIZE> temp_buffer;
    /*unsigned char *server_cert = (unsigned char*)malloc(cert_size);
    if(!server_cert) {
        cerr << "Malloc server_cert failed" << endl;

        #pragma optimize("", off);
            memset(recv_buffer, 0, MAX_BUF_SIZE);
        #pragma optimize("", on);
        
        //free(nonce);
        free(recv_buffer);
        //free(srv_nonce);
        return false;
    }*/
    //memcpy(temp_buffer.data(), recv_buffer.data() + start_index, cert_size);
    start_index += cert_size;

    // deserialize, verify certificate & extract server pubKey
    EVP_PKEY* srv_pubK;
    if(!verifyCert(buffer.data(), cert_size, srv_pubK)) {
        cerr << "Server certificate not verified\n";

        //memset(buffer.data(), '0', buffer.size());
        buffer.assign(buffer.size(), '0');
        recv_buffer.assign(recv_buffer.size(), '0');

        buffer.clear();
        recv_buffer.clear();    //fill('0');
        /*
        #pragma optimize("", off);
            memset(recv_buffer, 0, MAX_BUF_SIZE);
        #pragma optimize("", on);

        EVP_PKEY_free(srv_pubK);
        //free(server_cert);
        //free(nonce);
        free(recv_buffer);
        //free(srv_nonce);
        */
        return false;
    }
    cout << "Server certificate verified!" << endl;
    //memset(buffer.data(), '0', buffer.size());
    buffer.assign(buffer.size(), '0');
    buffer.clear();
    //temp_buffer.fill('0');   //once verified, the certificate can be deleted -> array "reset"

    // retrieve ECDH server pub key: size + key
    uint32_t ECDH_key_size_n = *(uint32_t*)(recv_buffer.data() + start_index);
    uint32_t ECDH_key_size = ntohl(ECDH_key_size_n);
    start_index += NUMERIC_FIELD_SIZE;
    //get key
    vector<unsigned char> ECDH_server_key;
    ECDH_server_key.insert(ECDH_server_key.begin(), 
                        recv_buffer.begin() + start_index,
                        recv_buffer.begin() + start_index + ECDH_key_size);
    /*
    unsigned char *ECDH_srv_key = (unsigned char*)malloc(ECDH_key_size);
    if(!ECDH_key_size)
        handleErrors("Malloc error");
        */
    //memcpy(ECDH_server_key.data(), recv_buffer.data() + start_index, ECDH_key_size);
    start_index += ECDH_key_size;

    // retrieve digital signature
    //int dig_sign_len = payload_size + NUMERIC_FIELD_SIZE - start_index; //*(unsigned int*)(recv_buffer + start_index);
    int dig_sign_len = recv_buffer.size() - start_index;
    if(dig_sign_len <= 0) {
        cerr << "Dig_sign length error " << endl;
        //memset(ECDH_server_key.data(), '0', ECDH_server_key.size());
        ECDH_server_key.assign(ECDH_server_key.size(), '0');
        ECDH_server_key.clear();
        return false;
    }

    vector<unsigned char> server_dig_sign;

    /*
    unsigned char *dig_sign = (unsigned char*)malloc(dig_sign_len);
    if(!dig_sign)
        handleErrors("Malloc error");
        */
    server_dig_sign.insert(server_dig_sign.begin(), 
                        recv_buffer.begin() + start_index, 
                        recv_buffer.end());
    //memcpy(server_dig_sign.data(), recv_buffer. + start_index, dig_sign_len);
    start_index += dig_sign_len;
    if(start_index - NUMERIC_FIELD_SIZE != payload_size) {
        cerr << "Received data size error" << endl;
        //memset(server_dig_sign.data(), '0', server_dig_sign.size());
        server_dig_sign.assign(server_dig_sign.size(), '0');
        //memset(ECDH_server_key.data(), '0', ECDH_server_key.size());
        ECDH_server_key.assign(ECDH_server_key.size(), '0');
        ECDH_server_key.clear();
        server_dig_sign.clear();
        return false;
    }
    
    // verify digital signature
    uint32_t signed_msg_len = NONCE_SIZE + ECDH_key_size;

    /*
    unsigned char* signed_msg = (unsigned char*)malloc(signed_msg_len);
    if(!signed_msg)
        handleErrors("Malloc error");
        */

    // nonce client
    if(!buffer.empty())
        buffer.clear();
    buffer.insert(buffer.begin(), client_nonce.begin(), client_nonce.end());
    //memcpy(temp_buffer.data(), client_nonce.data(), NONCE_SIZE);
    start_index = NONCE_SIZE;
    // server ECDH public key
    buffer.insert(buffer.end(), ECDH_server_key.begin(), ECDH_server_key.end());
    //memcpy(temp_buffer.data() + start_index, ECDH_server_key.data(), ECDH_key_size);
    bool verified = active_session->verifyDigSign(server_dig_sign.data(), dig_sign_len, srv_pubK, buffer.data(), signed_msg_len);
    
    // clear buffer
    //memset(buffer.data(), '0', buffer.size());
    //memset(server_dig_sign.data(), '0', server_dig_sign.size());
    buffer.assign(buffer.size(), '0');
    server_dig_sign.assign(server_dig_sign.size(), '0');

    buffer.clear();
    server_dig_sign.clear();

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

void Client::sendSign(vector<unsigned char> srv_nonce, EVP_PKEY *priv_k) {
    cout << "Client -> sendSign " << endl;
    unsigned char* ECDH_my_pub_key = NULL;
    uint32_t ECDH_my_key_size = active_session->serializePubKey(active_session->ECDH_myKey, ECDH_my_pub_key);
    vector<unsigned char> msg_to_sign(NONCE_SIZE + ECDH_my_key_size);
    //unsigned char* msg_to_sign = (unsigned char*)malloc(NONCE_SIZE + ECDH_my_key_size);
    //if(!msg_to_sign)
    //    handleErrors("sendSign: malloc return null");
    msg_to_sign.insert(msg_to_sign.begin(), srv_nonce.begin(), srv_nonce.end());
    //memcpy(msg_to_sign, srv_nonce.data(), NONCE_SIZE);
    memcpy(msg_to_sign.data() + NONCE_SIZE, ECDH_my_pub_key, ECDH_my_key_size);

    vector<unsigned char> signed_msg(EVP_PKEY_size(priv_k));
    int signed_msg_len = active_session->signMsg(msg_to_sign.data(), NONCE_SIZE + ECDH_my_key_size, priv_k, signed_msg.data());

    // prepare send buffer
    send_buffer.clear();    //fill('0');
    send_buffer.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE + NONCE_SIZE +NUMERIC_FIELD_SIZE + ECDH_my_key_size);
    //memset(send_buffer, 0, MAX_BUF_SIZE);

    uint32_t payload_size = OPCODE_SIZE + NONCE_SIZE + NUMERIC_FIELD_SIZE + ECDH_my_key_size + signed_msg_len;
    uint32_t payload_n = htonl(payload_size);
    memcpy(send_buffer.data(), &payload_n, NUMERIC_FIELD_SIZE);
    int start_index = NUMERIC_FIELD_SIZE;

    uint16_t opcode = htons((uint16_t)LOGIN);
    memcpy(send_buffer.data() + start_index, &opcode, OPCODE_SIZE);
    start_index += OPCODE_SIZE;

    send_buffer.insert(send_buffer.begin() + start_index, srv_nonce.begin(), srv_nonce.end());
    //memcpy(send_buffer.data() + start_index, srv_nonce.data(), NONCE_SIZE);
    start_index += NONCE_SIZE;

    uint32_t ECDH_my_key_size_n = htonl(ECDH_my_key_size);
    memcpy(send_buffer.data() + start_index, &ECDH_my_key_size_n, NUMERIC_FIELD_SIZE);    
    start_index += NUMERIC_FIELD_SIZE;

    memcpy(send_buffer.data() + start_index, ECDH_my_pub_key, ECDH_my_key_size);
    start_index += ECDH_my_key_size;
    
    send_buffer.insert(send_buffer.end(), signed_msg.begin(), signed_msg.end());
    //memcpy(send_buffer.data() + start_index, signed_msg, signed_msg_len);

    // send msg to server
    cout <<"authentication sendMsg (ecdh pub key)" << endl;
    sendMsg(payload_size);

    // clear buffer
    //memset(msg_to_sign.data(), '0', msg_to_sign.size());
    //memset(signed_msg.data(), '0', signed_msg.size());
    msg_to_sign.assign(msg_to_sign.size(), '0');
    signed_msg.assign(signed_msg.size(), '0');

    msg_to_sign.clear();
    signed_msg.clear();

    cout << "sendSign end" << endl;
}


/********************************************************************/

void Client::buildStore(X509*& ca_cert, X509_CRL*& crl, X509_STORE*& store) {
    // load CA certificate
    string ca_cert_filename = "./client/FoundationOfCybersecurity_cert.pem";    // controllare percorso directory
    FILE* ca_cert_file = fopen(ca_cert_filename.c_str(), "r");
    if(!ca_cert_file) {
        handleErrors("CA_cert file doesn't exist");
    }
    
    ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);
    if(!ca_cert)
        handleErrors("PEM_read_X509 returned NULL");

    // load the CRL
    string crl_filename = "./client/FoundationOfCybersecurity_crl.pem";
    FILE* crl_file = fopen(crl_filename.c_str(), "r");
    if(!crl_file) 
        handleErrors("CRL file doesn't exist");
    
    crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl)
        handleErrors("PEM_read_X509_CRL returned NULL");

    // build a store with CA_cert and the CRL
    store = X509_STORE_new();
    if(!store) {
        string err = "X509_STORE_new returned NULL\n";
        err.append(ERR_error_string(ERR_get_error(), NULL));
        handleErrors(err.c_str());
    }
    if(X509_STORE_add_cert(store, ca_cert) != 1) {
        string err = "X509_STORE_add_cert error\n";
        err.append(ERR_error_string(ERR_get_error(), NULL));
        handleErrors(err.c_str());
    }
    if(X509_STORE_add_crl(store, crl) != 1) {
        string err = "X509_STORE_add_crl error\n";
        err.append(ERR_error_string(ERR_get_error(), NULL));
        handleErrors(err.c_str());
    }
    if(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1) {
        string err = "X509_STORE_set_flags error\n";
        err.append(ERR_error_string(ERR_get_error(), NULL));
        handleErrors(err.c_str());
    }
}

bool Client::verifyCert(unsigned char* cert_buf, long cert_size, EVP_PKEY*& srv_pubK) {
    X509* certToCheck = d2i_X509(NULL, (const unsigned char**)&cert_buf, cert_size);
    if(!certToCheck)
        handleErrors("d2i_X509 failed");

    bool verified = false;

    X509* CA_cert;
    X509_CRL * CA_crl;
    X509_STORE* store;

    if(!certToCheck)
        handleErrors("Nothing to check");

    buildStore(CA_cert, CA_crl, store); 

    // verify peer's certificate
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) {
        string err = "X509_STORE_CTX_new returned NULL\n";
        err.append(ERR_error_string(ERR_get_error(), NULL));
        handleErrors(err.c_str());
    }
    if(X509_STORE_CTX_init(certvfy_ctx, store, certToCheck, NULL) != 1) {
        string err = "X50_STORE_CTX_init error\n";
        err.append(ERR_error_string(ERR_get_error(), NULL));
        handleErrors(err.c_str());
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
    sendMsg(payload_size);

    receiveFileList();
}

// TODO
void Client::receiveFileList() {
    unsigned char *aad, *user_list;
    int aad_len;
    int payload_size = receiveMsg();
    //int received_size = receiveMsg(payload_size);
    int list_len = active_session->decryptMsg(recv_buffer.data() + NUMERIC_FIELD_SIZE, payload_size, aad, aad_len, user_list);
    uint16_t opcode_n = *(unsigned short*)(aad + NUMERIC_FIELD_SIZE);
    uint16_t opcode = ntohs(opcode_n);
    if(opcode == 0) {
        string errorMsg((const char*)user_list, strlen((char*)user_list));
        cerr << errorMsg << endl;
        handleErrors("Error opcode");
    } else if(opcode != FILE_LIST)
        handleErrors("Opcode error, message tampered");

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
    string path = "./users/" + this->username + "/upload/" + filename;
    struct stat buffer;
    if(stat(path.c_str(), &buffer) != 0){
        cout<<"File not present"<<endl;
        return -1;
    }
    if(buffer.st_size > MAX_FILE_DIMENSION){
        cout<<"File too big"<<endl;
        return -1;
    }
    return buffer.st_size;
}

void Client::uploadFile(){
    string filename;
    uint32_t filedimension, payload_size, payload_size_n;
    vector<unsigned char> aad;
    vector<unsigned char> plaintext(FILE_SIZE_FIELD);
    array<unsigned char, MAX_BUF_SIZE> output; //to be allocated with malloc of the right size

    cout<<"****************************************"<<endl;
    cout<<"*********     Upload File      *********"<<endl;
    cout<<"****************************************"<<endl;

    readFilenameInput(filename, "Insert file name: ");
    filedimension = htonl(searchFile(filename));
    memcpy(plaintext.data(), &filedimension, FILE_SIZE_FIELD);
    plaintext.insert(plaintext.begin(), filename.begin(), filename.end());
    this->active_session->createAAD(aad.data(), UPLOAD_REQ);

    //send the basic information of the upload operation
    //to be sent: payload_size | IV | opcode | count_cs | {output}_Kcs | TAG

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), aad.size(), output.data());
    output.fill('0');
    aad.assign(aad.size(), '0');
    aad.clear();
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();

    payload_size_n = htonl(payload_size);
    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();
    send_buffer.resize(NUMERIC_FIELD_SIZE);
    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.end(), output.begin(), output.begin() + payload_size);


    if(sendMsg(payload_size) != 1){
        cout<<"Error during send phase (C->S)"<<endl;
    }

    //server response: <count_sc, op_code=1, {ResponseMsg}_Kcs>

    //start of the upload
    //to be sent: <count_cs, op_code=5, {chunk_i}_Kcs>

    //server response: <count_sc, op_code=5, {ResponseMsg}_Kcs>
}

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


//---------------------------------------------\\

int32_t
checkFileExistClient(string filename)
{
    string path = FILE_PATH_CL + filename;
    struct stat buffer;

    if (stat(path.c_str(),&buffer)!=0)  //stat failed
    { 
        return 0;   //File dosen't exist
	}
	
	return -1;  //File exist
}

void
Client::print_progress_bar(int total, unsigned int fragment)
{
    cout << "\r" << "[Fragment " << fragment + 1 << " of " << total << "]";
	cout.flush();

    /*
        - Possibile alternativa -
        void
        progress_bar(int fragment)
        {        
            //while (fragment < 1)
            //{
                int barWidth = 70;

                cout << "[";
        
                int pos = barWidth * fragment;
                for (size_t i = 0; i < barWidth; ++i)
                {
                    if (i < pos)
                        cout << "=";
                    else if (i == pos)
                        cout << ">";
                    else
                        cout << " ";
                }
        
            cout << "] " << int(fragment+1) << " %\r";
            cout.flush();

            fragment += 0.16; // for demonstration only
        //}
        }
    */
}

void
Client::removeFile(string filename)
{  
    string pathFile = FILE_PATH_CL + filename;

    //If the file is successfully deleted return 0. On failure a nonzero value (!=0) is returned.
    if (remove(pathFile.c_str()) !=0)
    {   
        perror ("\n\t * * * ERROR during deleting/overwriting file: "); }
    else
    {   cout << "\n\t --- Deleted Successfully ---\n" << endl; }
    
    return;


    /* --- EXEC_version ---
    void
    deleteFileExeclEasy(string filename)
    {  
        if(filename.length() > 20)
        {   cout << "\n\t -- Error: Filename too long --\n" << endl; return;    }

        string pathFile = FILE_PATH_CL + filename;

        execl("/bin/rm", "rm", pathFile.c_str(), (char*)0);

        return;   
    }
    */
}

int
Client::receiveMsgChunks( uint32_t filedimension, string filename)
{
    string path = FILE_PATH_CL + this->username + "/" + filename;
    ofstream outfile(path, ofstream::binary);

    size_t tot_chunks = ceil((float)filedimension / FRAGM_SIZE);
    size_t to_receive;
    int received_len, pt_len, aad_len;
    uint32_t opcode;

    vector<unsigned char> aad;
    array<unsigned char, MAX_BUF_SIZE> plaintext;

    plaintext.fill('0');

    for(int i = 0; i < tot_chunks; i++)
    {
        if(i == tot_chunks - 1)
            to_receive = filedimension - i* FRAGM_SIZE;
        else
            to_receive = FRAGM_SIZE;

        received_len = receiveMsg();
        if(received_len == -1 || received_len == 0)
        {
            cerr<<"Error! Exiting receive phase"<<endl;
            return -1;
        }
        pt_len = this->active_session->decryptMsg(this->recv_buffer.data(),
                                received_len, aad.data(), aad_len, plaintext.data());

        opcode = ntohs(*(uint32_t*)(aad.data() + NUMERIC_FIELD_SIZE));
        
        if((opcode == DOWNLOAD_REQ && i == tot_chunks - 1) || (opcode == END_OP && i != tot_chunks - 1))
        {
            outfile.close();
            cerr << "Wrong message format. Exiting"<<endl;
            
            if(remove(path.c_str()) != 0)
            {
                cerr << "File not correctly cancelled"<<endl;
            }
            return -1;
        }

        outfile << plaintext.data();
        print_progress_bar(tot_chunks, i);
    }

    aad.assign(aad.size(), '0');
    aad.clear();
    plaintext.fill('0');

    return 1;
}

int
Client::downloadFile()
{
    string filename;
    uint32_t file_size, payload_size, payload_size_n, filedimension;   
    vector<unsigned char> aad;
    vector<unsigned char> plaintext(FILE_SIZE_FIELD);
    array<unsigned char, MAX_BUF_SIZE> cyphertext;

    readFilenameInput(filename, "Insert the name of the file you want to Download: ");

    // === Controllo e gestione dell'esistenza del file all'interno della cartella Download ===
    if (checkFileExistClient(filename)!=0)
    {
        string choice;
        
        cout << "The requested file already exists in the Download folder, do you want to overwrite it?: [y/n]\n\n "<<endl;
        cout<<"_Ans: ";
        getline(cin, choice);

        if(!cin)
        {   cerr << "\n === Error during input ===\n" << endl; return -1; }

        while(choice != "Y" && choice!= "y" && choice != "N" && choice!= "n" )
        {
            cout<<"\nError: The parameter of cohice is wrong!"<<endl;
            cout<<"-- Try again: [y/n]: ";
            getline(cin, choice);

            if(!cin)
            {   cerr << "\n === Error during input ===\n" << endl; return -1; }
        }

        if(choice == "N" || choice == "n")
        {
            //--Annullamento Download operation
            //terminate();

            cout<<"\n\t~ The file *( "<< filename << " )* will not be overwritten. ~\n\n"<<endl;
            return;
        }
        
        removeFile(filename);
    }
    
    // === Preparazione Invio Dati e Cifratura  ===
    plaintext.insert(plaintext.begin(), filename.begin(), filename.end());

    this->active_session->createAAD(aad.data(), DOWNLOAD_REQ);
    
    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                            aad.data(), aad.size(), cyphertext.data());
    payload_size_n = htonl(payload_size);

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();

    // === Management Buffers & Content that to be sent ===
    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin()+ NUMERIC_FIELD_SIZE, cyphertext.begin(),
                        cyphertext.begin() + payload_size);
    cyphertext.fill('0');


// _BEGIN_(1)-------------- [ M1: INVIO_RICHIESTA_DOWNLOAD_AL_SERVER ] --------------

    if(sendMsg(payload_size) != 1)
    {
        cout<<"Error during send phase (C->S)"<<endl;
        
        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }

// _END_(1))-------------- [ M1: INVIO_RICHIESTA_DOWNLOAD_AL_SERVER ] --------------  


    int aad_len; uint16_t opcode;
    uint64_t received_len;  //legnht of the message received from the server 
    uint32_t plaintext_len;
    string server_response; //message from the server containing the response to the request
    int fileChunk;   //Management Chunk

    // === Reuse of vectors declared at the beginning ===
    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len == 0 || received_len == -1)
    {
        cout<<"Error during receive phase (S->C)"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }

    //Ciò che ricevo dal server in termini di byte
    plaintext_len = this->active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), aad_len, plaintext.data());

    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));    
    if(opcode != DOWNLOAD_REQ)
    {
        cout<<"Error! Exiting download request phase"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();

        return -1;
    }


// _BEGIN_(2)-------------- [M2: RICEZIONE_CONFERMA_RICHIESTA_DOWNLOAD_DAL_SERVER ] --------------
    
    /*----- Check Response esistenza file nel Cloud Storage da parte del Server -----*/
    server_response = ((char*)plaintext.data());
    if(server_response != MESSAGE_OK)
    {       
        cout<<"The file cannot be downloaded: "<< server_response <<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');


        return -1;
    }
    
// _END_(2)-------------- [ M2: RICEZIONE_CONFERMA_RICHIESTA_DOWNLOAD_DAL_SERVER ] --------------


    cout << "\nThe requested file is in the cloud storage and can be downloaded."<<endl;
    cout<<"\n\t ...Download file " + filename +" in progress...\n\n"<<endl;  

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();

    // === Reuse of vectors declared at the beginning ===
    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len == 0 || received_len == -1)
    {
        cout<<"Error during receive phase (S->C)"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }

    //Ciò che ricevo dal server in termini di byte
    plaintext_len = this->active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), aad_len, plaintext.data());

    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));    
    if(opcode != DOWNLOAD)
    {
        cout<<"Error! Exiting download request phase"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }
    
    filedimension = ntohl(*(uint32_t*)(plaintext.data()));
    

// _BEGIN_(3)-------------- [ M3: RICEZIONE_FILE_DAL_SERVER ] --------------

    fileChunk = receiveMsgChunks(filedimension, filename);

    if(fileChunk == -1)
    {
        cout<<"Error! Exiting Download phase"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');
        
        return -1;
    }

// _END_(3)-------------- [ M3: RICEZIONE_FILE_DAL_SERVER ] --------------


    cout << "\n\tFile Download Completed!" << endl;

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();

    // === Reuse of vectors declared at the beginning ===
    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    // === Preparazione Invio Dati e Cifratura Per ===    
    this->active_session->createAAD(aad.data(), END_OP);
    string ack_msg = DOWNLOAD_TERMINATED;
    
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                            aad.data(), aad.size(), cyphertext.data());
    payload_size_n = htonl(payload_size);

    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();

    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin()+ NUMERIC_FIELD_SIZE, cyphertext.begin(),
                        cyphertext.begin() + payload_size);
    cyphertext.fill('0');

// _BEGIN_(4)-------------- [ M4: INVIO_CONFERMA_DOWNLOAD_AL_SERVER ] --------------

    if(sendMsg(payload_size) != 1)
    {
        cout<<"Error during send phase (C->S)"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }
    
// _END_(4)-------------- [ M4: INVIO_CONFERMA_DOWNLOAD_AL_SERVER ] --------------

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();
    cyphertext.fill('0');
    
    return 1;
}

int
Client::deleteFile()
{
    string filename;
    uint32_t file_size, payload_size, payload_size_n, filedimension;   
    vector<unsigned char> aad;
    vector<unsigned char> plaintext(FILE_SIZE_FIELD);
    array<unsigned char, MAX_BUF_SIZE> cyphertext;

    readFilenameInput(filename, "Insert the name of the file you want to Delete: ");

    // === Preparazione Invio Dati e Cifratura  ===
    plaintext.insert(plaintext.begin(), filename.begin(), filename.end());

    this->active_session->createAAD(aad.data(), DELETE_REQ);
    
    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                            aad.data(), aad.size(), cyphertext.data());
    payload_size_n = htonl(payload_size);

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();

    // === Management Buffers & Content that to be sent ===
    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin()+ NUMERIC_FIELD_SIZE, cyphertext.begin(),
                        cyphertext.begin() + payload_size);
    cyphertext.fill('0');


// _BEGIN_(1)-------------- [ M1: INVIO_RICHIESTA_DELETE_AL_SERVER ] --------------

    if(sendMsg(payload_size) != 1)
    {
        cout<<"Error during send phase (C->S)"<<endl;
        
        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }

// _END_(1))-------------- [ M1: INVIO_RICHIESTA_DELETE_AL_SERVER ] --------------

    int aad_len;
    uint16_t opcode;
    uint64_t received_len;  
    uint32_t plaintext_len;
    string server_response, choice; 

    // === Reuse of vectors declared at the beginning ===
    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len == 0 || received_len == -1)
    {
        cout<<"Error during receive phase (S->C)"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }

    //Ciò che ricevo dal server in termini di byte
    plaintext_len = this->active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), aad_len, plaintext.data());

    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));    
    if(opcode != DELETE_REQ)
    {
        cout<<"Error! Exiting DELETE request phase"<<endl;

         // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }

// _BEGIN_(2)-------------- [M2: RICEZIONE_CONFERMA_RICHIESTA_DELETE_DAL_SERVER ] --------------
    
    /*----- Check Response esistenza file nel Cloud Storage da parte del Server -----*/
    server_response = ((char*)plaintext.data());
    if(server_response != MESSAGE_OK)
    {       
        cout<<"The file dosen't exist in the cloud: "<< server_response <<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return;
    }
    
// _END_(2)-------------- [ M2: RICEZIONE_CONFERMA_RICHIESTA_DELETE_DAL_SERVER ] --------------
        
    
    cout << "Are you sure you want to delete the file??: [y/n]\n\n "<<endl;
    cout<<"_Ans: ";
    getline(cin, choice);

    if(!cin)
    {
        cerr << "\n === Error during input ===\n" << endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }

    while(choice != "Y" && choice!= "y" && choice != "N" && choice!= "n" )
    {
        cout<<"\nError: The parameter of cohice is wrong!"<<endl;
        cout<<"-- Try again: [y/n]: ";
        getline(cin, choice);

        if(!cin)
        {
            cerr << "\n === Error during input ===\n" << endl;

            // === Cleaning ===
            plaintext.assign(plaintext.size(), '0');
            plaintext.clear();
            aad.assign(aad.size(), '0');
            aad.clear();
            cyphertext.fill('0');

            return -1;
        }
    }

    if(choice == "N" || choice == "n")
    {
        //--Annullamento Delete operation
        //terminate();

        cout<<"\n\t~ The file *( "<< filename << " )* will not be deleted. ~\n\n"<<endl;

         // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');
        
        return -1;
    }
        
    
//--Invio della scelta presa dall'utente al server--
    
    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();

    // === Reuse of vectors declared at the beginning ===
    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    // === Preparazione Invio Dati e Cifratura Per ===    
    this->active_session->createAAD(aad.data(), DELETE_CONFIRM);
    
    plaintext.insert(plaintext.begin(), choice.begin(), choice.end());

    payload_size = this->active_session->encryptMsg(plaintext.data(), plaintext.size(),
                                            aad.data(), aad.size(), cyphertext.data());
    payload_size_n = htonl(payload_size);

    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();

    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();
    send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    send_buffer.insert(send_buffer.begin()+ NUMERIC_FIELD_SIZE, cyphertext.begin(),
                        cyphertext.begin() + payload_size);
    cyphertext.fill('0');

// _BEGIN_(4)-------------- [ M3: INVIO_SCELTA-UTENTE_AL_SERVER ] --------------

    if(sendMsg(payload_size) != 1)
    {
        cout<<"Error during send phase (C->S)"<<endl;
        
        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }
    
// _END_(4)-------------- [ M3: INVIO_SCELTA-UTENTE_AL_SERVER ] --------------


    // === Reuse of vectors declared at the beginning ===
    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg();
    if(received_len == 0 || received_len == -1)
    {
        cout<<"Error during receive phase (S->C)"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');   
            
        return -1;
    }

    //Ciò che ricevo dal server in termini di byte
    plaintext_len = this->active_session->decryptMsg(recv_buffer.data(), received_len,
                                                aad.data(), aad_len, plaintext.data());

    //Opcode sent by the server, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));    
    if(opcode != DELETE_CONFIRM)
    {
        cout<<"Error! Exiting DELETE phase"<<endl;

         // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');
        
        return -1;
    }


// _BEGIN_(2)-------------- [M4: RICEZIONE_CONFERMA_DELETE_DAL_SERVER ] --------------
    
    server_response = ((char*)plaintext.data());
    
    cout<<"\nEND Operaton Msg: "<< server_response <<endl;

// _END_(2)-------------- [ M4: RICEZIONE_CONFERMA_DELETE_DAL_SERVER ] --------------

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();
    cyphertext.fill('0');
    
    return 1;
}