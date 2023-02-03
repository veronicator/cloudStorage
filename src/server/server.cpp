#include "server.h"

UserInfo::UserInfo(int sd, string name)
{
    sockd = sd;
    username = name;

    client_session = new Session();
}

UserInfo::~UserInfo() {
    username.clear();
    if(!send_buffer.empty()) {
        clear_vec(send_buffer);
    }
    if(!recv_buffer.empty()) {
        clear_vec(recv_buffer);
    }
    client_session = nullptr;
}

void UserInfo::cleanup() {

}

/********************************************************************/

Server::Server() {
    if(pthread_mutex_init(&mutex_client_list, NULL) != 0) {
        cerr << "mutex init failed " << endl;
        exit(EXIT_FAILURE);
    }
    if(!createSrvSocket()) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
}

bool Server::createSrvSocket() {
    cout << "createServerSocket" << endl;
    if((listener_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {  // socket TCP
        return false;
    }

    // set reuse socket
    int yes = 1;
    if(setsockopt(listener_sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0) {
        cerr << "set reuse socket error" << endl;
        return false;
    }

    // creation server address
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(SRV_PORT);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(listener_sd, (sockaddr*)&my_addr, sizeof(my_addr)) != 0) {
        cerr << "Bind error" << endl;
        return false;
    }
    //cout << "bind\n";
    if(listen(listener_sd, MAX_CLIENTS) != 0) {
        cerr << "Listen error" << endl;
        return false;
    }
    cout << "Server listening for connections" << endl;
    addr_len = sizeof(cl_addr);

    return true;
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
 * check if an user that wants to access to the cloud is already 
 *  registered on the server
 * @usr_name: client username
*/
bool Server::searchUserExist(string usr_name){
    string path = "./server/userKeys/";
    for (const auto& entry : fs::directory_iterator(path)){
        const std::string s = entry.path();
        std::regex rgx("[^/]*$");
        std::smatch match;

        if (std::regex_search(s, match, rgx))
            if(string(match[0]) == usr_name)
                return true;
    }
    return false;
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
    uint32_t payload_size_n;
    cout << payload_size << " sendMsg: payload size" << endl;
    if(payload_size > MAX_BUF_SIZE - NUMERIC_FIELD_SIZE) {
        cerr << "Message to send too big" << endl;
        clear_vec(send_buffer);
        return -1;
    }

    payload_size += NUMERIC_FIELD_SIZE;

    payload_size_n = htonl(payload_size);
    array<unsigned char, NUMERIC_FIELD_SIZE> arr;
    memcpy(arr.data(), &payload_size_n, NUMERIC_FIELD_SIZE);

    if(send(sockd, arr.data(), NUMERIC_FIELD_SIZE, 0) < NUMERIC_FIELD_SIZE){
        perror("Errore invio dimensione messaggio");
        send_buffer.assign(send_buffer.size(), '0');
        send_buffer.clear();
        return -1;
    }

    if(send(sockd, send_buffer.data(), payload_size, 0) < payload_size) {
        perror("Socker error: send message failed");
        clear_vec(send_buffer);
        return -1;
    }

    clear_vec(send_buffer);
    return 1;
}

/**
 * receive message from a client associated to a specific socket 
 * @sockd: socket descriptor through which the client is connected
 * @return: return the payload length of the received message, or 0 or -1 on error
*/
long Server::receiveMsg(int sockd, vector<unsigned char> &recv_buffer) {

    ssize_t msg_size = 0;
    uint32_t payload_size;
    array<unsigned char, MAX_BUF_SIZE> receiver;
    
    msg_size = recv(sockd, receiver.data(), NUMERIC_FIELD_SIZE, 0);
    cout << "Msg dimension size: " << msg_size << endl;

    payload_size = *(uint32_t*)(receiver.data());
    payload_size = ntohl(payload_size);
    cout << "Msg dimension data: " << payload_size << endl;
    if((long)payload_size > (long)(MAX_BUF_SIZE - 1)){
        cerr << "Dimension overflow" << endl;
        return -1;
    }

    msg_size = recv(sockd, receiver.data(), payload_size, 0);
    cout << "msg size: " << msg_size << endl;
    
    if (msg_size == 0) {
        cerr << "The connection with the socket " << sockd << " will be closed" << endl;
        return 0;
    }

    if (msg_size < 0 || msg_size < (unsigned int)NUMERIC_FIELD_SIZE + OPCODE_SIZE) {
        perror("Socket error: receive message failed");
        receiver.fill('0');
        return -1;
    }

    payload_size = *(uint32_t*)(receiver.data());
    payload_size = ntohl(payload_size);
    cout << "payload size received " << payload_size << endl;
    cout << "receiveMsg->msg_size received: " << msg_size << endl;
    cout << "---------" + to_string(msg_size - (ssize_t)NUMERIC_FIELD_SIZE) << endl;

    //check if received all data
    if ((long)payload_size != (long)msg_size - (long)NUMERIC_FIELD_SIZE) {
        cerr << "Error: Data received too short (malformed message?)" << endl;
        receiver.fill('0');
        return -1;
    }

    if(!recv_buffer.empty())
        clear_vec(recv_buffer);

    recv_buffer.insert(recv_buffer.begin(), receiver.begin(), receiver.begin() + msg_size);
    receiver.fill('0');

    return payload_size;
}

/********************************************************************/

void Server::run_thread(int sockd) {
    cout << "run_thread (inside the server) -> run()\n"
        << "thread socket " << sockd << endl;

    //long ret;
    bool retb;

    // todo: check if the user is already registered on the server
    retb = authenticationClient(sockd);

    if(!retb) {
        cerr << "authentication failed\n"
            << "Closing socket: " << sockd << endl;
        
        // TODO: erase the client from the map
        UserInfo *usr = nullptr;
        try {
            usr = connectedClient.at(sockd);
            
            connectedClient.erase(sockd);
        } catch(const out_of_range& ex) {
            cerr<<"usr not found"<<endl;
            //close(sockd);
            return;
        }
        
        //close(sockd);
        //pthread_exit(NULL); 
        return;
    }
    cout << "Client logged successfully!" << endl;
    
    int received_len, pt_len;
    uint16_t opcode;
    bool end_thread = false;
    UserInfo* ui = nullptr;
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext(MAX_BUF_SIZE);

    try {
        ui = connectedClient.at(sockd);
    }
    catch(const out_of_range& ex){
        cerr<<"Impossible to find the user"<<endl;
        return;
    }

    while(!end_thread){
        clear_arr(aad.data(), aad.size());
        clear_two_vec(ui->recv_buffer, plaintext);
        plaintext.resize(FILE_SIZE_FIELD + 20);

        received_len = receiveMsg(sockd, ui->recv_buffer);
        if(received_len < MIN_LEN){
            cerr<<"Error during receiving request msg"<<endl;
            break;
        }
        
        //cout << "server->runthread" << endl;
        //BIO_dump_fp(stdout, (const char*)ui->recv_buffer.data(), ui->recv_buffer.size()); 

        pt_len = ui->client_session->decryptMsg(ui->recv_buffer.data(), received_len, aad.data(), plaintext.data());
        if(pt_len <= 0){
            cerr << "run_thread->Error during decryption" << endl;
            clear_arr(aad.data(), aad.size());
            clear_vec(ui->recv_buffer);
            clear_vec(plaintext);
            break;
        }
        opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));
        switch(opcode){
            case UPLOAD_REQ:
                cout << to_string(pt_len) + " pt_len -> " << string(plaintext.begin(), plaintext.end()) << endl;
                uploadFile(sockd, plaintext, pt_len);
                break;

            case DOWNLOAD_REQ:
                downloadFile(sockd, plaintext);     //TODO: change to correct name
                break;

            case RENAME_REQ:
                renameFile(sockd, plaintext, pt_len);
                break;

            case DELETE_REQ:
                deleteFile(sockd, plaintext);       //TODO: change to correct name
                break;

            case FILE_LIST:
                sendFileList(sockd);
                break;
             
            case LOGOUT:
                cout << "Client requested logout" << endl;
                logoutClient(sockd);
                end_thread = true;
                break;
   
            default:
                cerr << "Error! Unexpected message" << endl;
                end_thread = true;
                break;
        }
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

    string path = "./server/userKeys/" + username + "/" + username + "_pub.pem";
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

    if(usr->client_session->deriveSecret() != 1) {
        cerr << "deriveSecret failed " << endl;
        return false;
    }
        /* 
    invia lista utenti online
    -> end authentication */
    //cout << "authentication send filelist" << endl;
    sendFileList(sockd);

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
        clear_vec(recv_buffer);
        cerr << "Error on Receive -> close connection with the client on socket: " << sockd << endl;
        //close(sockd);
        return false;
    }
        
    //cout << "receiveUsername buffer msg: " << endl;
    //BIO_dump_fp(stdout, (const char*)recv_buffer.data(), recv_buffer.size());
    
    start_index = NUMERIC_FIELD_SIZE;   // payload field
    if(payload_size < recv_buffer.size() - start_index) {   // - (uint)OPCODE_SIZE
        cerr << "receiveUsrname1: Received msg size error on socket: " << sockd << endl;
        clear_vec(recv_buffer);
        return false;
    }

    opcode = *(uint16_t*)(recv_buffer.data() + start_index);  //recv_buf.at(0);
    opcode = ntohs(opcode);
    start_index += OPCODE_SIZE;
    if(opcode != LOGIN) {
        cerr << "receiveUsrname2:Received message not expected on socket: " << sockd << endl;
        clear_vec(recv_buffer);
        return false;
    }
    
    if(start_index >= recv_buffer.size() - (uint)NONCE_SIZE) {
            // if it is equal => there is no username in the message -> error
        cerr << "ReceiveUsrname3: Received msg size error on socket: " << sockd << endl;
        clear_vec(recv_buffer);
        return false;
    }

    client_nonce.insert(client_nonce.begin(), recv_buffer.begin() + start_index, recv_buffer.begin() + start_index + NONCE_SIZE);
    start_index += NONCE_SIZE;
    username = string(recv_buffer.begin() + start_index, recv_buffer.end());
    cout << "username " << username << endl;
    clear_vec(recv_buffer);
    // check user existence
    if (!searchUserExist(username)) {
        cerr << "User not registered on the cloud -> can not authenticate" << endl;
        return false;
    }

    
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
    long ret = 0;
    
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
    uint32_t cert_size_n;
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
    srv_priv_k = usr->client_session->retrievePrivKey("./server/Server_key.pem");

    // retrieve e serialize server certificate
    cert_file = fopen(cert_file_name.c_str(), "r");
    if(!cert_file) { 
        cerr << "Server_cert file does not exist\n" << endl;
        return false;
    }
    cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!cert) {
        cerr << "PEM_read_X509 (cert) returned NULL\n" << endl;
        return false;
    }

    cert_size = i2d_X509(cert, &cert_buf);
    if(cert_size < 0) {
        cerr << "Server cert serialization error, i2d_X509 failed" << endl;
        return false;
    }
    // clean
    X509_free(cert);
    cout << "serialize cert" << endl;

    // generete and serialize ecdh key
    if(usr->client_session->generateNonce(srv_nonce.data()) != 1) {
        cerr << "generate nonce failed" << endl;
        return false;
    }
    usr->client_session->generateECDHKey();

    ret = usr->client_session->serializePubKey (
                                    usr->client_session->ECDH_myKey, ECDH_srv_pub_key);
    //BIO_dump_fp(stdout, (const char*)ECDH_srv_pub_key, ECDH_srv_key_size);
    // cout << "after serialize pub" << endl;

    if (ret < 0) {
        cerr << "serializePubKey failed " << endl;
        return false;
    }
    ECDH_srv_key_size = ret;

    // prepare message to sign
    msg_to_sign.reserve(NONCE_SIZE + ECDH_srv_key_size);
    msg_to_sign.resize(ECDH_srv_key_size);

    // fields to sign: client nonce + ECDH server key
    // -> insert client nonce
    msg_to_sign.insert(msg_to_sign.begin(), clt_nonce.begin(), clt_nonce.end());
    //cout << "server: received_nonce: " << endl;
    //BIO_dump_fp(stdout, (const char*)clt_nonce.data(), NONCE_SIZE);
    // -> insert ECDH server key 
    memcpy(msg_to_sign.data() + NONCE_SIZE, ECDH_srv_pub_key, ECDH_srv_key_size);

    signed_msg_len = usr->client_session->signMsg(msg_to_sign.data(), 
                                    msg_to_sign.size(), srv_priv_k, signed_msg.data());
    cout << "server: signMsg done" << endl;
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
    cert_size_n = htonl(cert_size);
    memcpy(usr->send_buffer.data() + start_index, &cert_size_n, NUMERIC_FIELD_SIZE);
    start_index += NUMERIC_FIELD_SIZE;
    // cert_server
    if(usr->send_buffer.size() < start_index + cert_size) {
        cerr << "send_buffer error size" << endl;
        return false;
    }
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

    cout << "sendCertSign buffer msg: " << endl;
    //BIO_dump_fp(stdout, (const char*)usr->send_buffer.data(), usr->send_buffer.size());

    if(sendMsg(payload_size, sockd, usr->send_buffer) != 1) {
        cerr << "sendCertSize failed " << endl;
        //delete usr;
        return false;
    }
    cout << "msg sent" << endl;
    
    //delete usr;
    return true;

}   // send (nonce, ecdh_key, cert, dig_sign)

/** 
 * receive client digital signature
 * @sockd: socket descriptor
 * @srv_nonce: array containing the nonce of the server
 * @return: true on success, false on failure
*/
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

    EVP_PKEY* client_pubK;
    
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
        usr->recv_buffer.clear();
        //close(sockd);
        //pthread_exit(NULL);
        return false;
    }
        
    start_index = NUMERIC_FIELD_SIZE;
    if(payload_size > usr->recv_buffer.size() - start_index) {  // - (uint)OPCODE_SIZE
        cerr << "receiveSign1:Received msg size error on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        //close(sockd);
        usr->recv_buffer.clear();
        return false;
    }

    opcode = *(uint16_t*)(usr->recv_buffer.data() + start_index);
    opcode = ntohs(opcode);
    start_index += OPCODE_SIZE;

    if(opcode != LOGIN) {
        cerr << "receiveSign: wrong OpCode \nReceived message not expected on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        usr->recv_buffer.clear();
        return false;
    }
    //start_index >= recv_buffer.size() - (int)NONCE_SIZE
    //if(recv_buf.size() <= NONCE_SIZE) {
    if(start_index >= usr->recv_buffer.size() - (uint)NONCE_SIZE) {
        cerr << "ReceiveSign2: Received msg size error on socket: " << sockd << endl;
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
        cerr << "Received nonce not verified, error on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        usr->recv_buffer.clear();
        return false;
    }
    cout << "Received nonce verified" << endl;
    /* | ecdh_size | ecdh_Pubk | digital signature |
    */
    if(start_index >= usr->recv_buffer.size() - (uint)NUMERIC_FIELD_SIZE) {
        cerr << "receiveSign3: Received msg size error on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        usr->recv_buffer.clear();
        return false;
    }

     // retrieve ECDH client pub key: size + key
    ECDH_key_size = *(uint32_t*)(usr->recv_buffer.data() + start_index);
    ECDH_key_size = ntohl(ECDH_key_size);
    start_index += NUMERIC_FIELD_SIZE;

    if(start_index >= usr->recv_buffer.size() - ECDH_key_size) {
        cerr << "receiveSign4: Received msg size error on socket: " << sockd << endl;
        usr->recv_buffer.assign(usr->recv_buffer.size(), '0');
        usr->recv_buffer.clear();
        return false;
    }
    //get key
    ECDH_client_key.insert(ECDH_client_key.begin(), 
                        usr->recv_buffer.begin() + start_index,
                        usr->recv_buffer.begin() + start_index + ECDH_key_size);
    start_index += ECDH_key_size;
    cout << "start index after ecdh key " << start_index << endl; 

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
    cout << "dig_sign_len: " << dig_sign_len << endl;
    cout << "client_signature len: " << client_signature.size() << endl;
    
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
    //cout << "ECDH_client_key" << endl;
    //BIO_dump_fp(stdout, (const char*) ECDH_client_key.data(), ECDH_key_size);
    usr->client_session->deserializePubKey(ECDH_client_key.data(), ECDH_key_size, 
                                            usr->client_session->ECDH_peerKey);

    return true;
}


int Server::sendFileList(int sockd) {
    cout << "server->sendFileList" << endl;
    uint32_t payload_size, payload_size_n;
    UserInfo* ui;
    string file_list;
    array<unsigned char, AAD_LEN> aad;
    vector<unsigned char> plaintext;    //(NUMERIC_FIELD_SIZE);
    vector<unsigned char> send_frag;
    array<unsigned char, MAX_BUF_SIZE> output;     
    // retrive UserInfo relative to the client
    try{
        ui = connectedClient.at(sockd);
    }
    catch(const out_of_range& ex){
        cerr<<"Impossible to find the user"<<endl;
        return -1;
    }
    
    file_list = "File of the user '" + ui->username + "' on the cloud:\n\n";
    const string path = path_file + ui->username + "/";
    //cout << "path_file: " << path << endl;

    int found_files = 0;
    for (const auto& entry : fs::directory_iterator(path)){
        const std::string s = entry.path();
        std::regex rgx("[^/]*$");
        std::smatch match;

        if (std::regex_search(s, match, rgx)){
            file_list += "-) " + string(match[0]) + "\n";
            found_files++;
            //cout << "File list" << found_files << " :" << file_list << endl;
        } 
    }    

    if(found_files == 0)
        file_list += "No files found\0";
    else
        file_list += "\n(" + to_string(found_files) + " files found)\0";
    
    
    int num_chunks = ceil(float(file_list.size())/FRAGM_SIZE);
    cout << "NUM CHUNKS: " << float(file_list.size())/FRAGM_SIZE << endl;
    plaintext.insert(plaintext.begin(), file_list.begin(), file_list.end());

    for(int i = 0; i < num_chunks; i++){
        if(i == num_chunks - 1){
            ui->client_session->createAAD(aad.data(), END_OP);
            send_frag.insert(send_frag.begin(), plaintext.begin() + FRAGM_SIZE * i, plaintext.end());
        }
        else{
            ui->client_session->createAAD(aad.data(), FILE_LIST);
            send_frag.insert(send_frag.begin(), plaintext.begin() + FRAGM_SIZE * i, plaintext.begin() + FRAGM_SIZE * (i + 1) - 1);  //TODO: -1 è necessario?
        }

        cout << "FRAGM NUM " + to_string(i) + " CONTAINS: " << endl;     

        payload_size = ui->client_session->encryptMsg(send_frag.data(), send_frag.size(), aad.data(), output.data());
        if (payload_size == 0) {
            cerr << " Error during encryption" << endl;
            clear_two_vec(send_frag, ui->send_buffer);
            clear_arr(aad.data(), aad.size());
            return -1;
        }
        payload_size_n = htonl(payload_size);

        clear_two_vec(send_frag, ui->send_buffer);
        clear_arr(aad.data(), aad.size());

        ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
        memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
        ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size) ;

        output.fill('0');

        //BIO_dump_fp(stdout, (const char*)ui->send_buffer.data(), ui->send_buffer.size());      

        if(sendMsg(payload_size, ui->sockd, ui->send_buffer) != 1){
            cerr<<"Error during send phase (S->C) | File List Phase"<<endl;
            return -1;
        }
    }
    clear_two_vec(ui->send_buffer, plaintext);
    cout << "end sendFileList" << endl;
    return 1;
}

void Server::logoutClient(int sockd) {
    cout << "logoutClient" << endl;
    UserInfo* ui;
    // retrive UserInfo relative to the client
    try{
        ui = connectedClient.at(sockd);
    }
    catch(const out_of_range& ex){
        cerr<<"Impossible to find the user"<<endl;
        return;
    }

    vector<unsigned char> plaintext;
    array<unsigned char, AAD_LEN> aad;
    array<unsigned char, MAX_BUF_SIZE> output;
    uint32_t payload_size, payload_size_n;
    string ack_msg = "Logout confirmed";

    ui->client_session->createAAD(aad.data(), END_OP);
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl
            << "exit anyway" << endl;
        delete ui;
        
        //payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    }
    clear_two_vec(plaintext, ui->send_buffer);
    clear_arr(aad.data(), aad.size());
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
    payload_size_n = htonl(payload_size);
    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    if(sendMsg(payload_size, sockd, ui->send_buffer) != 1)
        cerr << "Error during send phase (S->C | Logout)" << endl;

    clear_vec(plaintext);
    clear_arr(aad.data(), aad.size());
    clear_arr(output.data(), output.size());

    //ui->client_session->~Session();
    //ui->~UserInfo();
    delete ui;
    //ui = nullptr;
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

int Server::receiveMsgChunks(UserInfo* ui, uint64_t filedimension, string filename) {
    string path = path_file + ui->username + "/" + filename;
    ofstream outfile(path, ofstream::binary);
    if(!outfile.is_open()){
        cout<<"It was not possible to create or open the new file"<<endl;
        return -1;
    }

    size_t tot_chunks = ceil((float)filedimension / FRAGM_SIZE);
    long received_len;
    int pt_len;
    uint16_t opcode;
    array<unsigned char, AAD_LEN> aad;
    array<unsigned char, MAX_BUF_SIZE> frag_buffer;

    frag_buffer.fill('0');

    for(int i = 0; i < tot_chunks; i++){
        received_len = receiveMsg(ui->sockd, ui->recv_buffer);
        cout << "Chunk n: " << i + 1 << " of " << tot_chunks << endl;
        cout << "Received len : " << received_len << endl;
        cout << "MIN LEN : " << MIN_LEN << endl;
        if((long)received_len < (long)MIN_LEN){
            cout << "---------------------------------" << endl;
            cerr<<"Error! Exiting receive phase"<<endl;
            return -1;
        }

        pt_len = ui->client_session->decryptMsg(ui->recv_buffer.data(), received_len, aad.data(), frag_buffer.data());

        if (pt_len == 0) {
            cerr << " receiveMsgChunks->Error during decryption" << endl;
            clear_arr(frag_buffer.data(), frag_buffer.size());
            clear_arr(aad.data(), aad.size());
            return -1;
        }

        opcode = ntohs(*(uint32_t*)(aad.data() + NUMERIC_FIELD_SIZE));
        if((opcode == UPLOAD_REQ && i == tot_chunks - 1) || (opcode == END_OP && i != tot_chunks - 1)){
            outfile.close();
            cerr << "Wrong message format. Exiting"<<endl;
            if(remove(path.c_str()) != 0){
                cerr << "File not correctly cancelled"<<endl;
            }
            return -1;
        }

        outfile << string(frag_buffer.begin(), frag_buffer.begin() + pt_len);
        clear_arr(frag_buffer.data(), frag_buffer.size());
        clear_arr(aad.data(), aad.size());
        outfile.flush();
    }
    outfile.close();
    return 1;
}

int
Server::sendMsgChunks(UserInfo* ui, string filename)
{
    string path = FILE_PATH_SVR + ui->username + "/" + filename;                         
    FILE* file = fopen(path.c_str(), "rb");                                             
    struct stat buffer;

    if(!file)
    {
        cerr<<"Error during file opening"<<endl;
        return -1;
    }

    if(stat(path.c_str(), &buffer) != 0)
    {
        cerr<<filename + "doesn't exist in " + ui->username + "folder" <<endl;
        return -1;
    }

    int ret;                                                                            
    size_t tot_chunks = ceil((float)buffer.st_size / FRAGM_SIZE);                       
    size_t to_send;                                                                     
    uint32_t payload_size, payload_size_n;                                              
    array<unsigned char, AAD_LEN> aad;                                                          
    array<unsigned char, FRAGM_SIZE> frag_buffer;                                       
    array<unsigned char, MAX_BUF_SIZE> cyphertext;                                     
    
    //=== Managemetn Buffer ===
    frag_buffer.fill('0');
    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);

    for(int i = 0; i < tot_chunks; i++)
    {
        if(i == tot_chunks - 1)
        {
            to_send = buffer.st_size - i * FRAGM_SIZE;
            ui->client_session->createAAD(aad.data(), END_OP);  //last chunk -> END_OP opcode
        }
        else
        {
            to_send = FRAGM_SIZE;
            ui->client_session->createAAD(aad.data(), DOWNLOAD);  //intermediate chunks
        }

        ret = fread(frag_buffer.data(), sizeof(char), to_send, file);

        if(ferror(file) != 0 || ret != to_send)
        {
            cerr<<"ERROR while reading file"<<endl;

            clear_arr(aad.data(), aad.size());
            frag_buffer.fill('0');

            return -1;
        }

        payload_size = ui->client_session->encryptMsg(frag_buffer.data(),
                    frag_buffer.size(), aad.data(), cyphertext.data());

        payload_size_n = htonl(payload_size);

        //=== Managemetn Buffer ===
        clear_arr(aad.data(), aad.size());
        frag_buffer.fill('0');

        memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
        ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE,
                                cyphertext.begin(), cyphertext.begin() + payload_size);

        //=== Managemetn Buffer ===   
        cyphertext.fill('0');
        ui->send_buffer.assign(ui->send_buffer.size(), '0');
        ui->send_buffer.clear();
        ui->send_buffer.resize(NUMERIC_FIELD_SIZE);

        if(sendMsg(payload_size, ui->sockd, ui->send_buffer) != 1)
        {
            cerr<<"Error during send phase (C->S) | Upload Chunk Phase (chunk num: "<<i<<")"<<endl;

            //=== Cleaining ===
            clear_arr(aad.data(), aad.size());
            frag_buffer.fill('0');
            cyphertext.fill('0');

            return -1;
        }

        print_progress_bar(tot_chunks, i);
    }

    //=== Cleaining ===
    clear_arr(aad.data(), aad.size());
    frag_buffer.fill('0');
    cyphertext.fill('0');
    
    return 1;
}

// TODO: check code
int Server::uploadFile(int sockd, vector<unsigned char> plaintext, uint32_t pt_len) {
    uint64_t filedimension;
    uint32_t r_dim_l, r_dim_h, filename_dim;
    string filename;
    string ack_msg;
    uint32_t payload_size, payload_size_n;
    array<unsigned char, AAD_LEN> aad;
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
    memcpy(&r_dim_h, plaintext.data() + NUMERIC_FIELD_SIZE, NUMERIC_FIELD_SIZE);
    filedimension = ((uint64_t)ntohl(r_dim_h) << 32) + ntohl(r_dim_l);
    filename = string(plaintext.begin() + FILE_SIZE_FIELD, plaintext.begin() + pt_len);
    cout << "filename: " << filename << endl;

    const auto re = regex{R"(^\w[\w\.\-\+_!@#$%^&()~]{0,19}$)"}; //TODO: check if (^\w[\w\\\/\.\-\+_!@#$%^&()~]{0,19}$) (contains also \/ chars)
    file_ok = regex_match(filename, re);

    if(!file_ok){
        cerr<<"file not correct! Reception of the file terminated"<<endl;
        ack_msg = MALFORMED_FILENAME;
    } else if(searchFile(filename, ui->username, true) >= 0) {
        cout<<"File already present"<<endl;
        ack_msg = FILE_PRESENT;
        file_ok = false;
    }

    if(file_ok)
        ack_msg = MESSAGE_OK;
    
    clear_vec_array(plaintext, aad.data(), aad.size());
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());
    ui->client_session->createAAD(aad.data(), UPLOAD_REQ);
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        clear_two_vec(plaintext, ui->send_buffer);
        clear_arr(aad.data(), aad.size());
        return -1;
    }
    payload_size_n = htonl(payload_size);
    
    clear_two_vec(plaintext, ui->send_buffer);
    clear_arr(aad.data(), aad.size());
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
    
    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    if(sendMsg(payload_size, sockd, ui->send_buffer) != 1 || strcmp(ack_msg.c_str(), MALFORMED_FILENAME) == 0){
        cerr<<"Error during send phase (S->C | Upload response phase)"<<endl;
        cout<<"****************************************"<<endl;
        return -1;
    }

    if(strcmp(ack_msg.c_str(), FILE_PRESENT) == 0){
        cout << "File was already present. Upload rejected" << endl;
        return 1;       
    }
 
    clear_vec_array(ui->send_buffer, output.data(), output.size());

    cout << "       -------- RECEIVING FILE --------"<<endl;

    int ret = receiveMsgChunks(ui, filedimension, filename);
    
    if(ret == -1){
        cerr<<"Error! Something went wrong while receiving the file"<<endl;
        ack_msg = "File not received correctly\n";
    }
    else{
        ack_msg = OP_TERMINATED;
        cout << ack_msg << endl;
    }

    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
    ui->client_session->createAAD(aad.data(), END_OP);
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        clear_two_vec(plaintext, ui->send_buffer);
        clear_arr(aad.data(), aad.size());
        return -1;
    }
    payload_size_n = htonl(payload_size);
    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    clear_vec_array(plaintext, aad.data(), aad.size());
    
    if(sendMsg(payload_size, sockd, ui->send_buffer) != 1){
        cerr<<"Error during send phase (S->C | Upload end phase)"<<endl;
        return -1;
    }
    cout<<"       -------- RECEPTION ENDED --------" << endl;
    cout<<"****************************************"<<endl;
    return 1;
}


int Server::downloadFile(int sockd, vector<unsigned char> plaintext)
{
    string filename;
    uint32_t payload_size, payload_size_n;
    string ack_msg;
    array<unsigned char, AAD_LEN> aad;
    array<unsigned char, MAX_BUF_SIZE> cyphertext;
    bool file_ok = true;

    UserInfo *ui;

    try
    {
        ui = connectedClient.at(sockd);
    }
    catch(const out_of_range& ex)
    {
        cerr<<"_User NOT FOUND!_"<<endl;
        return -1;
    }

// _BEGIN_(1))------ [ M1: SEND_CONFIRMATION_DOWNLOAD_REQUEST_TO_CLIENT ] )------

    filename = string(plaintext.begin() + FILE_SIZE_FIELD, plaintext.end());

    const auto allowed = regex{R"(^\w[\w\.\-\+_!@#$%^&()~]{0,19}$)"};
    file_ok = regex_match(filename, allowed);

    if(!file_ok)
    {
        cerr<<"File not correct! Termination of the Download_Operation in progress"<<endl;
        ack_msg = "Filename not allowed";
    }

    if(checkFileExist(filename, ui->username, FILE_PATH_SVR) != 0)
    {
        cerr<<"Error: this file is not present in the folder"<<endl;
        ack_msg = "File not present in the Cloud Storage";

        file_ok = false;
    }

    if(file_ok)
    {   ack_msg = MESSAGE_OK; }                    

    //=== Preparing Data Sending and Encryption ===
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());

    ui->client_session->createAAD(aad.data(), DOWNLOAD_REQ);
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(),
                                            aad.data(), cyphertext.data());
    payload_size_n = htonl(payload_size);
    
    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
    
    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE,
                            cyphertext.begin(), cyphertext.begin() + payload_size);

    if(sendMsg(payload_size, sockd, ui->send_buffer) != 1 || !file_ok)
    {
        cerr<<"Error during sending DOWNLOAD_REQUEST_RESPONSE phase (S->C)"<<endl;

        // === Cleaning ===
        clear_vec(plaintext);
        clear_arr(aad.data(), aad.size());
        cyphertext.fill('0');

        return -1;
    }

// _END_(1)------ [ M1: SEND_CONFIRMATION_DOWNLOAD_REQUEST_TO_CLIENT ] )------


// _BEGIN_(2)-------------- [ M2: SEND_FILE_TO_CLIENT ] --------------

    int pt_len;                                                          
    uint16_t opcode;
    uint32_t fileChunk;  
    uint64_t received_len;
    string client_feedback; //DOWNLOAD_TERMINATED

    // === Cleaning ===
    clear_arr(aad.data(), aad.size());
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();

    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);

    fileChunk = sendMsgChunks(ui, filename);

// _END_(2)-------------- [ M2: SEND_FILE_TO_CLIENT ] --------------


// _BEGIN_(3)---- [ M3: RECEIVE_FEEDBACK_OPERATION_FROM_CLIENT ] ----

    if(fileChunk == 1)
    {
        plaintext.resize(MAX_BUF_SIZE);

        received_len = receiveMsg(sockd, ui->recv_buffer);
        if(received_len == 0 || received_len == -1)
        {
            cerr<<"Error during receive phase (C->S)"<<endl;
            return -1;
        }
        
        pt_len = ui->client_session->decryptMsg(ui->recv_buffer.data(), received_len,
                                                aad.data(), plaintext.data());
        if (pt_len == 0) {
            cerr << "dowload->Error during decryption" << endl;
            clear_two_vec(plaintext, ui->recv_buffer);
            clear_arr(aad.data(), aad.size());
            return -1;
        }
        opcode = ntohs(*(uint16_t*)(aad.data() + sizeof(uint32_t)));
        if(opcode != END_OP)
        {
            cerr<<"Error! Exiting DOWNLOAD_OPERATION." << endl;

            clear_arr(aad.data(), aad.size());
            plaintext.assign(plaintext.size(), '0');
            plaintext.clear();
            
            return -1;
        }
        
        if(client_feedback != DOWNLOAD_TERMINATED)
        {
            cerr<<"DOWNLOAD_OPERATION interrupted. ERROR: "<<client_feedback<<endl;

            clear_arr(aad.data(), aad.size());
            plaintext.assign(plaintext.size(), '0');
            plaintext.clear();

            return -1;
        }
    }
    else
    {
        cerr<<"Error! Exiting from DOWNLOAD_OPERATION phase"<<endl;

        clear_arr(aad.data(), aad.size());
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        
        return -1;
    }

// _END_(3)---- [ M3: RECEIVE_FEEDBACK_OPERATION_FROM_CLIENT  ] ----

    //=== Cleaning ===
    clear_arr(aad.data(), aad.size());
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    cyphertext.fill('0');

    return 1;
}

int Server::renameFile(int sockd, vector<unsigned char> plaintext, uint32_t) {
    string old_filename, new_filename;
    uint32_t old_name_len;
    string ack_msg = "";
    uint32_t payload_size, payload_size_n;
    array<unsigned char, AAD_LEN> aad;
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
    } else { //TODO: handle -2 and -3 cases
        if(searchFile(old_filename, ui->username, true) == -1) {
            cerr << "Filename to change doesn't correspond to any file"<<endl;
            ack_msg = "Filename to change doesn't correspond to any file\n";
            file_ok = false;
        }

        if(searchFile(new_filename, ui->username, true) >= 0){
            cerr << "The new filename is already used by another file" << endl;
            ack_msg += "The new filename is already used by another file\n";
            file_ok = false;
        }
    }
    
    if(file_ok)
        ack_msg = MESSAGE_OK;
    
    ui->client_session->createAAD(aad.data(), END_OP);
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), output.data());
    if (payload_size == 0) {
        cerr << " Error during encryption" << endl;
        clear_two_vec(plaintext, ui->send_buffer);
        clear_arr(aad.data(), aad.size());
        return -1;
    }
    payload_size_n = htonl(payload_size);

    clear_two_vec(plaintext, ui->send_buffer);
    clear_arr(aad.data(), aad.size());
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);

    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, output.begin(), output.begin() + payload_size);

    clear_vec_array(ui->send_buffer, output.data(), output.size());
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);

    if(sendMsg(payload_size, sockd, ui->send_buffer) != 1){
        cerr<<"Error during send phase (S->C | Upload end phase)"<<endl;
        cout<<"****************************************"<<endl;
        return -1;
    }

    cout<<"****************************************"<<endl;
    cout<<"******     Rename Terminated      ******"<<endl;
    cout<<"****************************************"<<endl;

    return 1;
}


int Server::deleteFile(int sockd, vector<unsigned char> plaintext)
{
    string filename;
    uint32_t payload_size, payload_size_n;
    string ack_msg;
    array<unsigned char, AAD_LEN> aad;
    array<unsigned char, MAX_BUF_SIZE> cyphertext;
    bool file_ok = true;

    UserInfo *ui;

    try
    {
        ui = connectedClient.at(sockd);
    }
    catch(const out_of_range& ex)
    {
        cerr<<"_User NOT FOUND!_"<<endl;
        return -1;
    }

// _BEGIN_(1)-------------- [ M1: SEND_CONFIRMATION_DELETE_REQUEST_TO_CLIENT ] --------------

    filename = string(plaintext.begin() + FILE_SIZE_FIELD, plaintext.end());

    const auto allowed = regex{R"(^\w[\w\.\-\+_!@#$%^&()~]{0,19}$)"};
    file_ok = regex_match(filename, allowed);

    if(!file_ok)
    {
        cerr<<"File not correct! Termination of the Delete_Operation in progress"<<endl;
        ack_msg = "Filename not allowed";
    }

    if(checkFileExist(filename, ui->username, FILE_PATH_SVR) != 0)
    {
        cerr<<"Error: this file is not present in the folder"<<endl;
        ack_msg = "File not present in the Cloud Storage";

        file_ok = false;
    }

    if(file_ok)
    {   ack_msg = MESSAGE_OK; }

    //=== Preparing Data Sending and Encryption ===
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());

    ui->client_session->createAAD(aad.data(), DELETE_REQ);
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), cyphertext.data());
    payload_size_n = htonl(payload_size);
    
    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
    
    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, cyphertext.begin(), cyphertext.begin() + payload_size);

    if(sendMsg(payload_size, sockd, ui->send_buffer) != 1 || !file_ok)
    {
        cerr<<"Error during sending DELETE_REQUEST_RESPONSE phase (S->C)"<<endl;

        // === Cleaning ===
        clear_vec(plaintext);
        aad.fill('0');
        cyphertext.fill('0');

        return -1;
    }

// _END_(1))-------------- [ M1: SEND_CONFIRMATION_DELETE_REQUEST_TO_CLIENT ] --------------


// _BEGIN_(2)-------------- [ M2: RECEIVE_CHOICE_OPERATION_FROM_CLIENT ] --------------

    uint16_t opcode;
    uint64_t received_len;  //legnht of the message received from the client
    uint32_t plaintext_len;
    string user_choice, final_msg;  //final_msg: message of successful cancellation

    // === Reuse of vectors declared at the beginning ===
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg(sockd, ui->recv_buffer);
    if(received_len == 0 || received_len == -1)
    {
        cout<<"Error during receive phase (C->S)"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.fill('0');
        cyphertext.fill('0');

        return -1;
    }

    plaintext_len = ui->client_session->decryptMsg(ui->recv_buffer.data(), received_len,
                                                aad.data(), plaintext.data());
    if (plaintext_len == 0) {
        cerr << " deleteFile->Error during decryption" << endl;
        clear_two_vec(plaintext, ui->recv_buffer);
        clear_arr(aad.data(), aad.size());
        return -1;
    }
    //Opcode sent by the client, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));    
    if(opcode != DELETE_CONFIRM)
    {
        cout<<"Error! Exiting DELETE_OPERATION phase"<<endl;

        // === Cleaning ===
        clear_vec(plaintext);
        clear_arr(aad.data(), aad.size());

        return -1;
    }

    user_choice = ((char*)plaintext.data());

// _END_(2)-------------- [ M2: RECEIVE_CHOICE_OPERATION_FROM_CLIENT ] --------------


// _BEGIN_(3)-------------- [ M3: SEND_RESPONSE_OF_THE_OPERATION_TO_CLIENT ] --------------

    if(user_choice == "Y" || user_choice == "y")
    {
        cout<<"\n\t~ The file *( "<< filename << " )* is going to be deleted. ~\n\n"<<endl;

        if(removeFile(filename, ui->username, FILE_PATH_SVR) == -1)
        {
            cout << "\n\t --- Error during Deleting file ---\n" << endl; 
        }

        final_msg = "File Deleted Successfully";
    }

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.fill('0');
    cyphertext.fill('0');

    // === Reuse of vectors declared at the beginning ===
    plaintext.resize(MAX_BUF_SIZE);

    // === Preparing Data Sending and Encryption ===    
    plaintext.insert(plaintext.begin(), final_msg.begin(), final_msg.end());

    ui->client_session->createAAD(aad.data(), END_OP);
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), cyphertext.data());
    payload_size_n = htonl(payload_size);
    
    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
    
    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, cyphertext.begin(), cyphertext.begin() + payload_size);                             

    if(sendMsg(payload_size, sockd, ui->send_buffer) != -1)
    {
        cerr<<"Error during sending CONFIRM_OPERATION phase (S->C)"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.fill('0');
        cyphertext.fill('0');

        return -1;
    }                                                

// _END_(3)-------------- [ M3: SEND_RESPONSE_OF_THE_OPERATION_TO_CLIENT ] --------------

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.fill('0');
    cyphertext.fill('0');

    return 1; //Successful_State
}

/********************************************/

ThreadArgs::ThreadArgs(Server* serv, int new_sockd) {
    if(!serv) {
        perror("Null pointer error");
        close(new_sockd);
        return;
    }
    server = serv;
    sockd = new_sockd;
}

void* client_thread_code(void *arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    Server* serv = args->server;
    int sockd = args->sockd;
    serv->run_thread(sockd);
    close(sockd);
    cout<< "exit thread \n";
    pthread_exit(NULL);
    return NULL;
}