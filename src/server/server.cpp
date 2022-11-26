#include "server.h"

UserInfo::UserInfo(int sd, string name) {
    sockd = sd;
    username = name;

    client_session = new Session();
}

UserInfo::~UserInfo(){
    username.clear();
    if(!send_buffer.empty()) {
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
    }
    if(!recv_buffer.empty()) {
        recv_buffer.assign(recv_buffer.size(), '0');
        recv_buffer.clear();
    }
    client_session = nullptr;
}

Server::Server() {
    if(pthread_mutex_init(&mutex_client_list, NULL) != 0) {
        cerr << "mutex init failed " << endl;
        exit(1);
        //handleErrors("mutex init failed");
    }
    createSrvSocket();
}

void Server::createSrvSocket() {
    cout << "createServerSocket" << endl;
    if((listener_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)  // socket TCP
        handleErrors("Socket creation error");

    // set reuse socket
    int yes = 1;
    if(setsockopt(listener_sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0)
        handleErrors("set reuse socket error");

    // creation server address
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(SRV_PORT);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(listener_sd, (sockaddr*)&my_addr, sizeof(my_addr)) != 0)
        handleErrors("Bind error");
    //cout << "bind\n";
    if(listen(listener_sd, MAX_CLIENTS) != 0)
        handleErrors("Listen error");
    cout << "Server listening for connections" << endl;
    addr_len = sizeof(cl_addr);
}

int Server::acceptConnection() {
    cout << "acceptConnection" << endl;
    if(connectedClient.size() < MAX_CLIENTS) {
        int new_sd;
        if((new_sd = accept(listener_sd, (sockaddr*)&cl_addr, &addr_len)) < 0) {
            cerr << "AcceptConnection error" << endl;
            return -1;
        }
        cout << "Connection accepted" << endl;

        return new_sd;
    }
    return -1;
}

int Server::getListener() {
    return listener_sd;
}


/********************************************************************/

/**
 * send a message through the specific socket
 * @payload_size: body lenght of the message to send
 * @sockd: socket descriptor through which send the message to the corresponding client
 * @send_buf: sending buffer containing the message to send, associated to a specific client
 * @return: 1 on success, 0 or -1 on error
 */
int Server::sendMsg(uint32_t payload_size, int sockd, vector<unsigned char> &send_buffer) {
    cout << payload_size << " sendMsg: payload size" << endl;
    if(payload_size > MAX_BUF_SIZE - NUMERIC_FIELD_SIZE) {
        cerr << "Message to send too big" << endl;
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();    //fill('0');
        //close(sockd);
        return -1;
        //handleErrors("Message to send too big", sockd);
    }

    payload_size += NUMERIC_FIELD_SIZE;
    if(send(sockd, send_buffer.data(), payload_size, 0) < payload_size) {
        perror("Socker error: send message failed");
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();    //fill('0');
        //close(sockd);
        return -1;
        //handleErrors("Send error", sockd);
    }

    send_buffer.assign(send_buffer.size(), '0');
    send_buffer.clear();
//    memset(send_buf.data(), 0, MAX_BUF_SIZE);
    return 1;
}

/**
 * receive message from a client associated to a specific socket 
 * @sockd: socket descriptor through which the client is connected
 * @return: return the payload length of the received message, or 0 or -1 on error
*/
long Server::receiveMsg(int sockd, vector<unsigned char> &recv_buffer) {

    int msg_size = 0;
    uint32_t payload_size;
    array<unsigned char, MAX_BUF_SIZE> receiver;
    
    msg_size = recv(sockd, receiver.data(), MAX_BUF_SIZE-1, 0);
    cout << "msg size: " << msg_size << endl;
    
    if (msg_size == 0) {
        cerr << "The connection with the socket " << sockd << " has been closed" << endl;
        return 0;
    }

    if (msg_size < 0 || msg_size < (unsigned int)NUMERIC_FIELD_SIZE + OPCODE_SIZE) {
        perror("Socket error: receive message failed");
        receiver.fill('0');
        //memset(recv_buffer, 0, MAX_BUF_SIZE);
        return -1;
    }

    //recv_buf.assign(MAX_BUF_SIZE, 0);
    payload_size = *(uint32_t*)(receiver.data());
    payload_size = ntohl(payload_size);
    //cout << "payload size received " << payload_size << endl;

    //check if received all data
    if (payload_size != msg_size - (int)NUMERIC_FIELD_SIZE) {
        cerr << "Error: Data received too short (malformed message?)" << endl;
        receiver.fill('0');
        //close(sockd);
        //memset(recv_buffer, 0, MAX_BUF_SIZE);
        return -1;
    }

    recv_buffer.insert(recv_buffer.begin(), receiver.begin(), receiver.begin() + msg_size);
    receiver.fill('0');
    cout << "recv size buf: " << recv_buffer.size() << endl;

    return payload_size;
}

/********************************************************************/

void Server::client_thread_code(int sockd) {
    cout << "client thread code (inside the server) -> run()\n";
    cout << "thread socket " << sockd << endl;

    long ret;
    bool retb;

    retb = authenticationClient(sockd);

    if(!retb) {
        cerr << "authentication failed\n"
            << "Closing socket: " << sockd << endl;
        
        // TODO: erase the client from the map
        
        close(sockd);
        //pthread_exit(NULL); 
        return;
    }
    

    pthread_mutex_lock(&mutex_client_list);
    connectedClient.erase(sockd);
    //todo: add also the erase on che socket_list map
    pthread_mutex_unlock(&mutex_client_list);
    
}


/********************************************************************/

/** retrieve the public key of the client with the given username
 * @username: username of the client for who get the key
 * @return: client public key on success, NULL otherwise
*/
EVP_PKEY* Server::getPeerKey(string username) {
    // TODO
    /** check username -> to avoid a directory traversal attack
     * 
    */

    string path = "./server/userStorage/" + username + "/" + username + "_pub.pem";
    FILE* pubK_file = fopen(path.c_str(), "r");
    if(!pubK_file) {
        cerr << "Cannot open pub key pem file for client " << username << endl;
        return nullptr;
    }

    EVP_PKEY* peerKey = PEM_read_PUBKEY(pubK_file, NULL, NULL, NULL);
    fclose(pubK_file);
    if(!peerKey) {
        cerr << "PEM_read_PUBKEY returned NULL" << endl;
        return nullptr;
    }

    return peerKey;
}

/********************************************************************/


bool Server::authenticationClient(int sockd) {
    cout << "authenticationClient" << endl;
    bool retb;
    long ret;

    UserInfo *usr = nullptr;
    
    array<unsigned char, NONCE_SIZE> server_nonce;
    vector<unsigned char> client_nonce;

    if(!receiveUsername(sockd, client_nonce)) {
        cerr << "receiveUsername failed" << endl;
        return false;
    }

    sendCertSign(sockd, client_nonce, server_nonce);

        
    // retrieve user structure
    pthread_mutex_lock(&mutex_client_list);
    try {
		usr = connectedClient.at(sockd);
	} catch (const out_of_range& ex) {
		return false;
	}
    pthread_mutex_unlock(&mutex_client_list);

    
    if (!receiveSign(sockd, server_nonce)) {
        cerr << "receiveSign failed" << endl;

        pthread_mutex_lock(&mutex_client_list);
        connectedClient.erase(sockd);
        pthread_mutex_unlock(&mutex_client_list);
        return false;
    }
        /* 
    verifica firma
    invia lista utenti online
    -> end authentication */

    return true;
}  // call session.generatenonce & sendMsg


/********************************************************************/


/** receive the first message from a client to establish a connection
 * @sockd: descriptor of the socket from which the request arrives
 * @return: true on success, false otherwise
*/
bool Server::receiveUsername(int sockd, vector<unsigned char> &client_nonce) {
    // M1 (Authentication)
    vector<unsigned char> recv_buffer;
    // Authentication M1
    long payload_size;
    uint32_t start_index = 0;
    uint16_t opcode;
    string username;
    UserInfo* new_usr = nullptr;
    
    payload_size = receiveMsg(sockd, recv_buffer);
    
    if(payload_size <= 0) {
        recv_buffer.assign(recv_buffer.size(), '0');
        cerr << "Error on Receive -> close connection with the client on socket: " << sockd << endl;
        //close(sockd);
        recv_buffer.clear();
        return false;
    }
    
    start_index = NUMERIC_FIELD_SIZE;   // payload field
    if(payload_size > recv_buffer.size() - start_index) {   // - (uint)OPCODE_SIZE
        cerr << "284Received msg size error on socket: " << sockd << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        //close(sockd);
        recv_buffer.clear();
        return false;
    }

    opcode = *(uint16_t*)(recv_buffer.data() + start_index);  //recv_buf.at(0);
    opcode = ntohs(opcode);
    start_index += OPCODE_SIZE;
    if(opcode != LOGIN) {
        //handleErrors("Opcode error", sockd);
        cerr << "Received message not expected on socket: " << sockd << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        //close(sockd);
        recv_buffer.clear();
        return false;
    }
    
    if(start_index >= recv_buffer.size() - (uint)NONCE_SIZE) {
            // if it is equal => there is no username in the message -> error
        //handleErrors("Received msg size error", sockd);
        cerr << "Received msg size error on socket: " << sockd << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        //close(sockd);
        recv_buffer.clear();
        return false;
    }

    client_nonce.insert(client_nonce.begin(), recv_buffer.begin(), recv_buffer.begin() + NONCE_SIZE);
    start_index += NONCE_SIZE;
    username = string(recv_buffer.begin() + start_index, recv_buffer.end());
    cout << "username " << username << endl;

    recv_buffer.assign(recv_buffer.size(), '0');
    recv_buffer.clear();
    
    pthread_mutex_lock(&mutex_client_list);
    if(connectedClient.find(sockd) != connectedClient.end()) {
        cerr << "Error on socket: " << sockd << " \nConnection already present\n" << endl;
        return false;
    }
    new_usr = new UserInfo(sockd, username);
    //connectedClient.insert(pair<int, UserInfo>(new_sd, new_usr));
    auto ret = connectedClient.insert({sockd, new_usr});
    cout << "connected size " << connectedClient.size() << endl;

    pthread_mutex_unlock(&mutex_client_list);
    return ret.second;
}


/********************************************************************/

/** method to sent the server certificate and its digital signature 
 * to the client requesting the connection to the cloud
 * @clt_nonce: nonce received in the firt message from the client, 
 *             to re-send signed, to the same client
 * @sockd: socket descriptor
 * @return: true on success, false otherwise
*/
bool Server::sendCertSign(int sockd, vector<unsigned char> &clt_nonce, array<unsigned char, NONCE_SIZE> &srv_nonce) {
    // recupera certificato, serializza cert, copia nel buffer, genera nonce, genera ECDH key, firma, invia

    // M2 (Authentication)
    cout << "server->sendCertSign" << endl;
    
    //array<unsigned char, MAX_BUF_SIZE> buffer_temp;  // support array
    
    uint32_t payload_size = 0;
    uint32_t payload_size_n;    // this second variable is needed for the network format of the number and the first one cannot be overwritten
    uint32_t start_index = 0;
    uint16_t opcode;

    UserInfo *usr = nullptr;

    unsigned char* cert_buf = nullptr;
    EVP_PKEY* srv_priv_k = nullptr;
    unsigned char* ECDH_srv_pub_key = nullptr;
    uint32_t ECDH_srv_key_size ;
    uint32_t ECDH_srv_key_size_n;
    vector<unsigned char> msg_to_sign;
    uint32_t signed_msg_len;
    array<unsigned char, MAX_BUF_SIZE> signed_msg;  

    string cert_file_name = "./server/Server_cert.pem";
    FILE* cert_file = nullptr;
    X509* cert = nullptr;
    int cert_size;
    
    // retrieve user structure
    pthread_mutex_lock(&mutex_client_list);
    try {
		usr = connectedClient.at(sockd);
	} catch (const out_of_range& ex) {
		return false;
	}
    pthread_mutex_unlock(&mutex_client_list);

    // retrieve server private key
    usr->client_session->retrievePrivKey("./server/Server_key.pem", srv_priv_k);

    // retrieve e serialize server certificate
    cert_file = fopen(cert_file_name.c_str(), "r");
    if(!cert_file) { 
        //handleErrors("Server_cert file doesn't exist", sockd);
        cerr << "Server_cert file does not exist\n" << endl;
        return false;
    }
    cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!cert) {
        //handleErrors("PEM_read_X509 (cert) returned NULL", sockd);
        cerr << "PEM_read_X509 (cert) returned NULL\n" << endl;
        return false;
    }

    cert_size = i2d_X509(cert, &cert_buf);
    if(cert_size < 0) {
        //handleErrors("Server cert serialization error, i2d_X509 failed", sockd);
        cerr << "Server cert serialization error, i2d_X509 failed" << endl;
        return false;
    }
    // clean
    X509_free(cert);
    cout << "serialize cert" << endl;

    // generete and serialize ecdh key
    usr->client_session->generateNonce(srv_nonce.data());
    usr->client_session->generateECDHKey();

    ECDH_srv_key_size = usr->client_session->serializePubKey (
                                    usr->client_session->ECDH_myKey, ECDH_srv_pub_key);
    BIO_dump_fp(stdout, (const char*)ECDH_srv_pub_key, ECDH_srv_key_size);
    // cout << "after serialize pub" << endl;

    // prepare message to sign
    msg_to_sign.reserve(NONCE_SIZE + ECDH_srv_key_size);
    msg_to_sign.resize(ECDH_srv_key_size);

    // fields to sign: client nonce + ECDH server key
    // -> insert client nonce
    msg_to_sign.insert(msg_to_sign.begin(), clt_nonce.begin(), clt_nonce.end());
    // -> insert ECDH server key 
    memcpy(msg_to_sign.data() + NONCE_SIZE, ECDH_srv_pub_key, ECDH_srv_key_size);
    cout << "client nonce inserted\n";

    signed_msg_len = usr->client_session->signMsg(msg_to_sign.data(), 
                                    msg_to_sign.size(), srv_priv_k, signed_msg.data());

    // prepare send buffer    
    payload_size = OPCODE_SIZE + NONCE_SIZE + NONCE_SIZE + NUMERIC_FIELD_SIZE 
                + cert_size + NUMERIC_FIELD_SIZE + ECDH_srv_key_size + signed_msg_len;
    
    // fields to insert with the memcpy in the vector
    uint32_t temp_size = NUMERIC_FIELD_SIZE + OPCODE_SIZE + NUMERIC_FIELD_SIZE 
                            + NUMERIC_FIELD_SIZE + cert_size + ECDH_srv_key_size;
    usr->send_buffer.resize(temp_size);

    if(usr->send_buffer.size() < temp_size) {
        cerr << "vector.resize error " << endl;
        //TODO: clear all buffer -> cercare come deallocare tutto correttamente

        signed_msg.fill('0');
        msg_to_sign.assign(msg_to_sign.size(), '0');
        EVP_PKEY_free(srv_priv_k);
        OPENSSL_free(cert_buf);
        free(ECDH_srv_pub_key); // TODO: check if it is correct

        return false;
    }

    // msg: | pay_size | op | Nonce_c | Nonce_S | cert_size | cert | ECDH_size | ECDH | DigSign |
    // payload_size
    payload_size_n = htonl(payload_size);
    memcpy(usr->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    start_index = NUMERIC_FIELD_SIZE;
    // opcode        
    opcode = htons((uint16_t)LOGIN);
    memcpy(usr->send_buffer.data() + start_index, &opcode, OPCODE_SIZE);
    start_index += OPCODE_SIZE;
    // nonce_client
    usr->send_buffer.insert(usr->send_buffer.begin() + start_index, clt_nonce.begin(), clt_nonce.end());
    start_index += NONCE_SIZE;
    // nonce_server
    usr->send_buffer.insert(usr->send_buffer.begin() + start_index, srv_nonce.begin(), srv_nonce.end());
    start_index += NONCE_SIZE;
    // cert_size
    cert_size = htonl(cert_size);
    memcpy(usr->send_buffer.data() + start_index, &cert_size, NUMERIC_FIELD_SIZE);
    start_index += NUMERIC_FIELD_SIZE;
    // cert_server
    memcpy(usr->send_buffer.data() + start_index, cert_buf, cert_size);
    start_index += cert_size;
    // ECDH_size
    ECDH_srv_key_size_n = htonl(ECDH_srv_key_size);
    memcpy(usr->send_buffer.data() + start_index, &ECDH_srv_key_size_n, NUMERIC_FIELD_SIZE);
    start_index += NUMERIC_FIELD_SIZE;
    // ECDH_server_pubK
    memcpy(usr->send_buffer.data() + start_index, ECDH_srv_pub_key, ECDH_srv_key_size);
    start_index += ECDH_srv_key_size;
    // digital_sign
    usr->send_buffer.insert(usr->send_buffer.end(), signed_msg.begin(), signed_msg.begin() + signed_msg_len);

    // clear buffers
    signed_msg.fill('0');
    msg_to_sign.assign(msg_to_sign.size(), '0');
    EVP_PKEY_free(srv_priv_k);
    OPENSSL_free(cert_buf);
    free(ECDH_srv_pub_key); // TODO: check if it is correct

    if(sendMsg(payload_size, sockd, usr->send_buffer) != 1) {
        cerr << "sendCertSize failed " << endl;
        //delete usr;
        return false;
    }
    
    //delete usr;
    return true;

}   // send (nonce, ecdh_key, cert, dig_sign)


//HERE

bool Server::receiveSign(int sockd, array<unsigned char, NONCE_SIZE> &srv_nonce) {
    // M3 Authentication
    // receive and verify client digital signature 
    cout << "server->receiveSign" << endl;

    UserInfo *usr = nullptr;
    long payload_size;
    uint32_t start_index = 0;
    uint16_t opcode;

    vector<unsigned char> received_nonce;
    uint32_t ECDH_key_size;
    vector<unsigned char> ECDH_client_key;
    long dig_sign_len;
    vector<unsigned char> client_signature;
    uint32_t signed_msg_len;
    vector<unsigned char> temp_buf;

    EVP_PKEY* client_pubK;  // TODO: RETRIEVE THIS KEY FROM FILE
    
    // retrieve user structure
    pthread_mutex_lock(&mutex_client_list);
    try {
		usr = connectedClient.at(sockd);
	} catch (const out_of_range& ex) {
		return false;
	}
    pthread_mutex_unlock(&mutex_client_list);

    //vector<unsigned char> recv_buf;
    payload_size = receiveMsg(sockd, usr->recv_buffer);
    if(payload_size <= 0) {
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        cerr << "Error on Receive -> close connection with the client on socket: " << sockd << endl;
        //close(sockd);
        usr->recv_buffer.clear();
        //close(sockd);
        //pthread_exit(NULL);
        return false;
    }
        
    start_index = NUMERIC_FIELD_SIZE;
    if(payload_size > usr->recv_buffer.size() - start_index - (uint)OPCODE_SIZE) {
        cerr << "Received msg size error on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        //close(sockd);
        usr->recv_buffer.clear();
        return false;
    }

    opcode = *(uint16_t*)(usr->recv_buffer.data() + start_index);
    opcode = ntohs(opcode);
    start_index += OPCODE_SIZE;

    if(opcode != LOGIN) {
        cerr << "Received message not expected on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        usr->recv_buffer.clear();
        return false;
    }
    //start_index >= recv_buffer.size() - (int)NONCE_SIZE
    //if(recv_buf.size() <= NONCE_SIZE) {
    if(start_index >= usr->recv_buffer.size() - (uint)NONCE_SIZE) {
        cerr << "Received msg size error on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        usr->recv_buffer.clear();
        return false;
    }

    received_nonce.insert(received_nonce.begin(),
                        usr->recv_buffer.begin() + start_index, 
                        usr->recv_buffer.begin() + start_index + NONCE_SIZE);
    start_index += NONCE_SIZE;
    if(!usr->client_session->checkNonce(received_nonce.data(), srv_nonce.data())) {
        //sendErrorMsg(sockd, "Received nonce not verified");
        cerr << "Received mnonce not verified, error on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        usr->recv_buffer.clear();
        return false;
    }
    /* | ecdh_size | ecdh_Pubk | digital signature |
    */
    if(start_index >= usr->recv_buffer.size() - (uint)NUMERIC_FIELD_SIZE) {
        cerr << "Received msg size error on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        usr->recv_buffer.clear();
        return false;
    }

     // retrieve ECDH client pub key: size + key
    ECDH_key_size = *(uint32_t*)(usr->recv_buffer.data() + start_index);
    ECDH_key_size = ntohl(ECDH_key_size);
    start_index += NUMERIC_FIELD_SIZE;

    if(start_index >= usr->recv_buffer.size() - ECDH_key_size) {
        cerr << "Received msg size error on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        usr->recv_buffer.clear();
        return false;
    }
    //get key
    ECDH_client_key.insert(ECDH_client_key.begin(), 
                        usr->recv_buffer.begin() + start_index,
                        usr->recv_buffer.begin() + start_index + ECDH_key_size);
    start_index += ECDH_key_size;

    // retrieve digital signature
    //int dig_sign_len = payload_size + NUMERIC_FIELD_SIZE - start_index; //*(unsigned int*)(recv_buffer + start_index);
    dig_sign_len = usr->recv_buffer.size() - start_index;
    if(dig_sign_len <= 0) {
        cerr << "Dig_sign length error " << endl;
        ECDH_client_key.assign(ECDH_client_key.size(), '0');
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        ECDH_client_key.clear();
        usr->recv_buffer.clear();
        return false;
    }

    client_signature.insert(client_signature.begin(), 
                        usr->recv_buffer.begin() + start_index, 
                        usr->recv_buffer.end());
    start_index += dig_sign_len;
    
    // verify digital signature : nonce + ECDH_key
    signed_msg_len = NONCE_SIZE + ECDH_key_size;

    // retrieve client pub key
    client_pubK = getPeerKey(usr->username);
    if(!client_pubK) {
        cerr << "get_peerKey failed " << endl;
        // clear buffers and return
        ECDH_client_key.assign(ECDH_client_key.size(), '0');
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        ECDH_client_key.clear();
        usr->recv_buffer.clear();

        return false;
    }

    if(!temp_buf.empty())
        temp_buf.clear();
    
    // nonce 
    temp_buf.insert(temp_buf.begin(), received_nonce.begin(), received_nonce.end());
    start_index = NONCE_SIZE;

    // server ECDH public key
    temp_buf.insert(temp_buf.end(), ECDH_client_key.begin(), ECDH_client_key.end());
    //memcpy(temp_buffer.data() + start_index, ECDH_server_key.data(), ECDH_key_size);
    bool verified = usr->client_session->verifyDigSign(client_signature.data(), dig_sign_len, 
                                                        client_pubK, temp_buf.data(), signed_msg_len);
    
    // clear buffer
    //memset(buffer.data(), '0', buffer.size());
    //memset(server_dig_sign.data(), '0', server_dig_sign.size());
    temp_buf.assign(temp_buf.size(), '0');
    client_signature.assign(client_signature.size(), '0');

    temp_buf.clear();
    client_signature.clear();

    if(!verified) {
        cerr << "Digital Signature not verified" << endl;

        // clear buffer key
        ECDH_client_key.assign(ECDH_client_key.size(), '0');
        //memset(ECDH_server_key.data(), '0', ECDH_server_key.size());
        ECDH_client_key.clear();

        return false;
    }
    cout << " Digital Signature Verified!" << endl;
    //free(signed_msg);
    BIO_dump_fp(stdout, (const char*) ECDH_client_key.data(), ECDH_key_size);
    usr->client_session->deserializePubKey(ECDH_client_key.data(), ECDH_key_size, 
                                            usr->client_session->ECDH_peerKey);

    return true;
}


int Server::sendFileList(int sockd) {
    uint32_t payload_size, payload_size_n;
    UserInfo* ui;
    const string path = path_file + ui->username + "/";
    string file_list = "";
    vector<unsigned char> aad;
    vector<unsigned char> plaintext(NUMERIC_FIELD_SIZE);
    array<unsigned char, MAX_BUF_SIZE> output;     
    // retrive UserInfo relative to the client
    try{
        ui = connectedClient.at(sockd);
    }
    catch(const out_of_range& ex){
        cerr<<"Impossible to find the user"<<endl;
        return -1;
    }

    for (const auto& entry : std::filesystem::directory_iterator(path)){
        const std::string s = entry.path();
        std::regex rgx("[^/]*$");
        std::smatch match;

        if (std::regex_search(s, match, rgx))
            file_list += string(match[0]) + "\n"; 
    }    
    
    int num_chunks = ceil(file_list.size()/FRAGM_SIZE);
    plaintext.insert(plaintext.begin(), file_list.begin(), file_list.end());

    for(int i = 0; i < num_chunks; i++){
        if(i == num_chunks - 1)
            ui->client_session->createAAD(aad.data(), END_OP);
        else
            ui->client_session->createAAD(aad.data(), FILE_LIST);

        payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), aad.size(), output.data());
        payload_size_n = htonl(payload_size);

        aad.assign(aad.size(), '0');
        aad.clear();
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();    
        ui->send_buffer.assign(ui->send_buffer.size(), '0');
        ui->send_buffer.clear();
        ui->send_buffer.resize(NUMERIC_FIELD_SIZE);   

        memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
        ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size) ;

        output.fill('0');

        if(sendMsg(payload_size, ui->sockd, ui->send_buffer) != 1){
            cerr<<"Error during send phase (S->C) | File List Phase"<<endl;
            return -1;
        }
    }
}

void Server::logoutClient(int sockd) {
    UserInfo* ui;
    // retrive UserInfo relative to the client
    try{
        ui = connectedClient.at(sockd);
    }
    catch(const out_of_range& ex){
        cerr<<"Impossible to find the user"<<endl;
        return;
    }
    ui->client_session->~Session();
    ui->~UserInfo();
    ui = nullptr;
}
    

void Server::sendErrorMsg(int sockd, string errorMsg) {
        //cerr << errorMsg << endl;

        // inviare mess errore al client
        int payload_size = OPCODE_SIZE + errorMsg.size();
        vector<unsigned char> send_buf(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
        memcpy(send_buf.data(), &payload_size, NUMERIC_FIELD_SIZE);
        uint16_t op = ERROR;
        memcpy(send_buf.data() + NUMERIC_FIELD_SIZE, &op, OPCODE_SIZE);
        send_buf.insert(send_buf.end(), errorMsg.begin(), errorMsg.end());
        
        sendMsg(payload_size, sockd, send_buf);

}
/*
void Server::joinThread() {
    while(!threads.empty()) {
        threads.front().join();
        threads.pop_front();
    }
}*/

int Server::receiveMsgChunks(UserInfo* ui, uint64_t filedimension, string filename){
    string path = path_file + ui->username + "/" + filename;
    ofstream outfile(path, ofstream::binary);
    if(!outfile.is_open()){
        cout<<"It was not possible to create or open the new file"<<endl;
        return -1;
    }

    size_t tot_chunks = ceil((float)filedimension / FRAGM_SIZE);
    int received_len, pt_len, aad_len;
    uint16_t opcode;
    vector<unsigned char> aad;
    array<unsigned char, MAX_BUF_SIZE> plaintext;

    plaintext.fill('0');

    for(int i = 0; i < tot_chunks; i++){
        received_len = receiveMsg(ui->sockd, ui->recv_buffer);
        if(received_len == -1 || received_len == 0){
            cerr<<"Error! Exiting receive phase"<<endl;
            return -1;
        }

        pt_len = ui->client_session->decryptMsg(ui->recv_buffer.data(), received_len, aad.data(), aad_len, plaintext.data());
        opcode = ntohs(*(uint32_t*)(aad.data() + NUMERIC_FIELD_SIZE));
        if((opcode == UPLOAD_REQ && i == tot_chunks - 1) || (opcode == END_OP && i != tot_chunks - 1)){
            outfile.close();
            cerr << "Wrong message format. Exiting"<<endl;
            if(remove(path.c_str()) != 0){
                cerr << "File not correctly cancelled"<<endl;
            }
            return -1;
        }

        outfile << plaintext.data();
        aad.assign(aad.size(), '0');
        aad.clear();
        plaintext.fill('0');
        outfile.flush();
    }

    outfile.close();
}

int Server::uploadFile(int sockd, vector<unsigned char> plaintext) {
    uint64_t filedimension;
    uint32_t r_dim_l, r_dim_h;
    string filename;
    string ack_msg;
    uint32_t payload_size, payload_size_n;
    vector<unsigned char> aad;
    array<unsigned char, MAX_BUF_SIZE> output;
    bool file_ok = true;
    cout<<"****************************************"<<endl;
    cout<<"***********   RECEIVING FILE   *********"<<endl;
    cout<<"****************************************"<<endl;

    // retrive UserInfo relative to the client
    UserInfo* ui;
    try{
        ui = connectedClient.at(sockd);
    }
    catch(const out_of_range& ex){
        cerr<<"Impossible to find the user"<<endl;
        cout<<"****************************************"<<endl;
        return -1;
    }

    //the plaintext has format: filedimension | filename
    memcpy(&r_dim_l, plaintext.data(), NUMERIC_FIELD_SIZE);
    memcpy(&r_dim_h, plaintext.data() + 4, NUMERIC_FIELD_SIZE);
    filedimension = ((uint64_t)ntohl(r_dim_h) << 32) + ntohl(r_dim_l);
    filename = string(plaintext.begin() + FILE_SIZE_FIELD, plaintext.end());

    const auto re = regex{R"(^\w[\w\.\-\+_!@#$%^&()~]{0,19}$)"};
    file_ok = regex_match(filename, re);

    if(!file_ok){
        cerr<<"file not correct! Reception of the file terminated"<<endl;
        ack_msg = "Filename not correct";
    }

    if(searchFile(filename, ui->username) == -1){
        cerr<<"File not present"<<endl;
        ack_msg = "File not present";
        file_ok = false;
    }

    if(file_ok)
        ack_msg = MESSAGE_OK;
    
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());
    ui->client_session->createAAD(aad.data(), UPLOAD_REQ);
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), aad.size(), output.data());
    payload_size_n = htonl(payload_size);
    
    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
    
    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    if(sendMsg(payload_size, sockd, ui->send_buffer) != -1 || !file_ok){
        cerr<<"Error during send phase (S->C | Upload response phase)"<<endl;
        cout<<"****************************************"<<endl;
        return -1;
    }
        
    output.fill('0');
    aad.assign(aad.size(), '0');
    aad.clear();
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);

    cout << "       -------- RECEIVING FILE --------"<<endl;

    int ret = receiveMsgChunks(ui, filedimension, filename);
    if(ret == -1){
        cerr<<"Error! Something went wrong while receiving the file"<<endl;
        return -1;
    }

    ui->client_session->createAAD(aad.data(), END_OP);
    ack_msg = OP_TERMINATED;
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), aad.size(), output.data());
    payload_size_n = htonl(payload_size);
    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);
    
    if(sendMsg(payload_size, sockd, ui->send_buffer) != -1){
        cerr<<"Error during send phase (S->C | Upload end phase)"<<endl;
        return -1;
    }
    cout<<"       -------- RECEPTION ENDED --------";
    cout<<"****************************************"<<endl;
}

void Server::downloadFile() {

}

int Server::renameFile(int sockd, vector<unsigned char> plaintext) {
    string old_filename, new_filename;
    uint32_t old_name_len;
    string ack_msg;
    uint32_t payload_size, payload_size_n;
    vector<unsigned char> aad;
    array<unsigned char, MAX_BUF_SIZE> output;
    bool file_ok = true;
    UserInfo* ui;
    cout<<"****************************************"<<endl;
    cout<<"***********   Rename Request   *********"<<endl;
    cout<<"****************************************"<<endl;

    try{
        ui = connectedClient.at(sockd);
    }
    catch(const out_of_range& ex){
        cerr<<"Impossible to find the user"<<endl;
        return -1;
    }

    old_name_len = ntohl(*(uint32_t*)plaintext.data());
    old_filename.insert(old_filename.begin(), plaintext.begin() + FILE_SIZE_FIELD, plaintext.begin() + FILE_SIZE_FIELD + old_name_len);
    new_filename.insert(new_filename.begin(), plaintext.begin() + FILE_SIZE_FIELD + old_name_len, plaintext.end());

    const auto re = regex{R"(^\w[\w\.\-\+_!@#$%^&()~]{0,19}$)"};
    file_ok = (regex_match(old_filename, re) && regex_match(new_filename, re));

    if(!file_ok){
        cerr<<"Filename not correct! Rename terminated"<<endl;
        ack_msg = "Filename not correct";
    }

    if(searchFile(old_filename, ui->username) == -1){
        cerr << "Filename to change doesn't correspond to any file"<<endl;
        ack_msg = "Filename to change doesn't correspond to any file";
        file_ok = false;
    }

    if(searchFile(new_filename, ui->username) != -1){
        cerr << "The new filename is already used by another file" << endl;
        ack_msg = "The new filename is already used by another file";
        file_ok = false;
    }
    
    if(file_ok)
        ack_msg = MESSAGE_OK;
    
    ui->client_session->createAAD(aad.data(), END_OP);
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), aad.size(), ui->send_buffer.data());
    payload_size_n = htonl(payload_size);

    aad.assign(aad.size(), '0');
    aad.clear();
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
    output.fill('0');

    if(sendMsg(payload_size, sockd, ui->send_buffer) != -1){
        cerr<<"Error during send phase (S->C | Upload end phase)"<<endl;
        cout<<"****************************************"<<endl;
        return -1;
    }

    cout<<"****************************************"<<endl;
    cout<<"******     Rename Terminated      ******"<<endl;
    cout<<"****************************************"<<endl;
}

void Server::deleteFile() {

}


/********************************************/

ThreadArgs::ThreadArgs(Server* serv, int new_sockd) {
    if(!serv)
        handleErrors("Null pointer error", new_sockd);
    server = serv;
    sockd = new_sockd;
}

void* client_thread_code(void *arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    Server* serv = args->server;
    int sockd = args->sockd;
    serv->client_thread_code(sockd);
    cout<< "exit thread \n";
    pthread_exit(NULL);
    return NULL;
}