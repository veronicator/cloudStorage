#include "server.h"

UserInfo::UserInfo(int sd, string name) {
    sockd = sd;
    username = name;

/*    send_buffer = (unsigned char*)malloc(MAX_BUF_SIZE);
    if(!send_buffer)
        handleErrors("Malloc error");
    recv_buffer = (unsigned char*)malloc(MAX_BUF_SIZE);
    if(!recv_buffer)
        handleErrors("Malloc error");
*/
    client_session = new Session();
}

Server::Server() {
    if(pthread_mutex_init(&mutex_client_list, NULL) != 0) {
        cerr << "mutex init failed " << endl;
        exit(1);
        //handleErrors("mutex init failed");
    }
    createSrvSocket();
}
/*
Server* Server::getServer() {
    if(!server)
        server = new Server();
    return server;
}
*/
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
        /*
        pthread_mutex_lock(&mutex);
        //mtx.lock();
        UserInfo new_usr(new_sd);
        //connectedClient.insert(pair<int, UserInfo>(new_sd, new_usr));
        connectedClient.insert({new_sd, new_usr});
        cout << "connected size " << connectedClient.size() << endl;
        //mtx.unlock();
        pthread_mutex_unlock(&mutex);
*/
       // thread cl_thread(Server::client_thread_code, new_sd);
        //threads.push_back(cl_thread);
        //if(pthread_create(&client_thread, NULL, &client_thread_code, (void*)new_sd) != 0)
          //  handleErrors("thread_create failed");
        
        return new_sd;
    }
    return -1;
}

int Server::getListener() {
    return listener_sd;
}
/*
void* Server::client_thread_code(void* arg) {
    int sd = *(int*)(arg);
    cout << "thread socket " << sd << endl;
}
*/

/********************************************************************/

/**
 * send a message through the specific socket
 * @payload_size: body lenght of the message to send
 * @sockd: socket descriptor through which send the message to the corresponding client
 * @send_buf: sending buffer containing the message to send, associated to a specific client
 * @return: 1 on success, 0 or -1 on error
 */
int Server::sendMsg(int payload_size, int sockd, vector<unsigned char> &send_buffer) {
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
 * receive message from a client, associated to a specific socket 
 * @sockd: socket descriptor through which the client is connected
 * @return: return the payload length of the received message, or 0 or -1 on error
*/
long Server::receiveMsg(int sockd, vector<unsigned char> &recv_buffer) {

    int msg_size = 0;
    //user->recv_buffer.clear();
    array<unsigned char, MAX_BUF_SIZE> receiver;
    //memset(user->recv_buffer, 0, MAX_BUF_SIZE);
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
    uint32_t payload_size_n = *(uint32_t*)receiver.data();
    uint32_t payload_size = ntohl(payload_size_n);
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

    bool retb = authenticationClient(sockd);
    long ret;

    if(!retb) {
        cerr << "authentication failed\n"
            << "Closing socket: " << sockd << endl;
        //pthread_exit(NULL); 
        return;
    }
    
    /* 
    verifica firma
    invia lista utenti online
    -> end authentication */

    pthread_mutex_lock(&mutex_client_list);
    connectedClient.erase(sockd);
    //todo: add also the erase on che socket_list map
    pthread_mutex_unlock(&mutex_client_list);
    
}


/********************************************************************/


bool Server::authenticationClient(int sockd) {
    cout << "authenticationClient" << endl;
    bool retb;
    long ret;

    if(!receiveUsername(sockd)) {
        cerr << "receiveUsername failed" << endl;
        return false;
    }

    //sendCertSign(client_nonce, username, sockd);
    
    //receiveSign(sockd, username, recv_buffer);
    
    return true;
}  // call session.generatenonce & sendMsg


/********************************************************************/

bool Server::receiveUsername(int sockd) {
    long ret;
    vector<unsigned char> recv_buffer;
    // Authentication M1
    long payload_size = receiveMsg(sockd, recv_buffer);
    if(payload_size <= 0) {
        recv_buffer.assign(recv_buffer.size(), '0');
        cerr << "Error on Receive -> close connection with the client on socket: " << sockd << endl;
        close(sockd);
        recv_buffer.clear();
        return false;
    }
    
    int start_index = NUMERIC_FIELD_SIZE;
    if(payload_size > recv_buffer.size() - start_index - (int)OPCODE_SIZE) {
        cerr << "Received msg size error on socket: " << sockd << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        close(sockd);
        recv_buffer.clear();
        return false;
    }

    uint16_t opcode_n = *(uint16_t*)(recv_buffer.data() + start_index);  //recv_buf.at(0);
    uint16_t opcode = ntohs(opcode_n);
    start_index += OPCODE_SIZE;
    if(opcode != LOGIN) {
        //handleErrors("Opcode error", sockd);
        cerr << "Received message not expected on socket: " << sockd << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        close(sockd);
        recv_buffer.clear();
        return false;
    }

    //recv_buffer.erase(recv_buffer.begin(), recv_buf.begin() + OPCODE_SIZE);
    if(recv_buffer.size() <= start_index + NONCE_SIZE) {
        //handleErrors("Received msg size error", sockd);
        cerr << "Received msg size error on socket: " << sockd << endl;
        recv_buffer.assign(recv_buffer.size(), '0');
        close(sockd);
        recv_buffer.clear();
        return false;
    }
    vector<unsigned char> client_nonce;
    client_nonce.insert(client_nonce.begin(), recv_buffer.begin(), recv_buffer.begin() + NONCE_SIZE);
    string username = string(recv_buffer.begin() + NONCE_SIZE, recv_buffer.end());
    cout << "username " << username << endl;

    recv_buffer.assign(recv_buffer.size(), '0');
    recv_buffer.clear();
    
    pthread_mutex_lock(&mutex_client_list);
    if(connectedClient.find(sockd) != connectedClient.end()) {
        cerr << "Error on socket: " << sockd << " \nConnection already present\n"
        << "Closing the socket and this thread" << pthread_self() << endl;
        close(sockd);
        return false;
    }
    UserInfo* new_usr = new UserInfo(sockd, username);
    //connectedClient.insert(pair<int, UserInfo>(new_sd, new_usr));
    connectedClient.insert({sockd, new_usr});
    cout << "connected size " << connectedClient.size() << endl;

    pthread_mutex_unlock(&mutex_client_list);

    return true;
}



/********************************************************************/
/* DONE: modificate send e receive -> fare metodo di autenticazione con tutte le chiamate corrette 
    e i vari messaggi da ricevere/inviare
*/
/********************************************************************/


bool Server::sendCertSign(vector<unsigned char> &clt_nonce, string &username, int sockd) {
    cout << "server->sendCertSign" << endl;
    // recupera certificato, serializza cert, copia nel buffer, genera nonce, genera ECDH key, firma, invia
    // retrieve user structure
    // TODO: modificare gestione, senza passare dalla lista di username, ma direttamente dal sockd
    pthread_mutex_lock(&mutex_client_list);
    if(connectedClient.find(sockd) == connectedClient.end()) {
        
        handleErrors("username not found", sockd);
        return false;
    }

    UserInfo *usr;

    try {
		usr = connectedClient.at(sockd);
	}
	catch (const out_of_range& ex) {
		return false;
	}
    
    pthread_mutex_unlock(&mutex_client_list);

    // retrieve server private key
    EVP_PKEY* srv_priv_k;
    usr->client_session->retrievePrivKey("./server/Server_key.pem", srv_priv_k);

    // retrieve e serialize server certificate
    string cert_file_name = "./server/Server_cert.pem";
    FILE* cert_file = fopen(cert_file_name.c_str(), "r");
    if(!cert_file) { 
        handleErrors("Server_cert file doesn't exist", sockd);
    }
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!cert)
        handleErrors("PEM_read_X509 (cert) returned NULL", sockd);

    unsigned char* cert_buf = NULL;
    int cert_size = i2d_X509(cert, &cert_buf);
    if(cert_size < 0)
        handleErrors("Server cert serialization error, i2d_X509 failed", sockd);
    // clean
    X509_free(cert);
    cout << "serialize cert" << endl;

    // generete and serialize ecdh key
    usr->client_session->generateNonce();
    usr->client_session->generateECDHKey();
    unsigned char* ECDH_srv_pub_key = NULL;
    uint32_t ECDH_srv_key_size = usr->client_session->serializePubKey(usr->client_session->ECDH_myKey, ECDH_srv_pub_key);
    BIO_dump_fp(stdout, (const char*)ECDH_srv_pub_key, ECDH_srv_key_size);
    // cout << "after serialize pub" << endl;
    // prepare message to sign
    array<unsigned char, MAX_BUF_SIZE> buffer;  // support array
    vector<unsigned char> msg_to_send;      // buffer to sign and send
    //vector<unsigned char> send_buf;

    msg_to_send.insert(msg_to_send.begin(), clt_nonce.begin(), clt_nonce.end());
    cout << "insert 1\n";
    // todo: fix
    //msg_to_send.insert(msg_to_send.end(),usr->client_session->nonce.begin(), usr->client_session->nonce.end());
    cout << "insert 2" << endl;

    memcpy(buffer.data(), ECDH_srv_pub_key, ECDH_srv_key_size);
    cout << "memcpy 2" << endl;
    msg_to_send.insert(msg_to_send.end(), buffer.begin(), buffer.begin() + ECDH_srv_key_size);
    cout << " insert 4" << endl;
    buffer.fill('0');

    unsigned char* signed_msg = NULL;
    int signed_msg_len = usr->client_session->signMsg(msg_to_send.data(), msg_to_send.size(), srv_priv_k, signed_msg);

    // prepare send buffer
    // status msg_to_send: | Nc | Ns | ECDH_srv_pubK |
    int payload_size;
    uint16_t op = LOGIN;
    memcpy(buffer.data(), &op, OPCODE_SIZE);
    msg_to_send.insert(msg_to_send.begin(), buffer.begin(), buffer.begin() + OPCODE_SIZE);    // insert opcode
    payload_size = OPCODE_SIZE + NONCE_SIZE + NONCE_SIZE;
    // status msg_to_send: | OP | Nc | Ns | ECDH_srv_pubK |
    
    uint32_t cert_size_n = htonl(cert_size);
    memcpy(buffer.data(), &cert_size_n, NUMERIC_FIELD_SIZE);
    msg_to_send.insert(msg_to_send.begin() + payload_size, buffer.begin(), buffer.begin() + NUMERIC_FIELD_SIZE);    // insert cert_size
    payload_size += NUMERIC_FIELD_SIZE;
    // status msg_to_send: | OP | Nc | Ns | cert_size | ECDH_srv_pubK |

    memcpy(buffer.data(), cert_buf, cert_size);
    cout << "memcpy 1" << endl;
    msg_to_send.insert(msg_to_send.begin() + payload_size, buffer.begin(), buffer.begin() + cert_size);
    payload_size += cert_size;
    cout << "insert 3" << endl;
    buffer.fill('0');
    cout << "fill 1\n";
    // status msg_to_send: | OP | Nc | Ns | cert_size | server_cert | ECDH_srv_pubK |

    memcpy(buffer.data(), &ECDH_srv_key_size, NUMERIC_FIELD_SIZE);
    msg_to_send.insert(msg_to_send.begin() + payload_size, buffer.begin(), buffer.begin() + NUMERIC_FIELD_SIZE);    // insert key_size
    // status msg_to_send: | OP | Nc | Ns | cert_size | server_cert | ECDH_key_size | ECDH_srv_pubK |
    
    // copy signed_msg in support array
    memcpy(buffer.data(), signed_msg, signed_msg_len);
    msg_to_send.insert(msg_to_send.end(), buffer.begin(), buffer.begin() + signed_msg_len); // insert digital signature at the end
    // status msg_to_send: | OP | Nc | Ns | cert_size | server_cert | ECDH_key_size | ECDH_srv_pubK | Dig_sign |

    payload_size = msg_to_send.size();

    memcpy(buffer.data(), &payload_size, NUMERIC_FIELD_SIZE);
    msg_to_send.insert(msg_to_send.begin(), buffer.begin(), buffer.begin() + NUMERIC_FIELD_SIZE);   // insert payload_size
    // status msg_to_send: | payload_size | OP | Nc | Ns | cert_size | server_cert | ECDH_key_size | ECDH_srv_pubK | Dig_sign |
    
    buffer.fill('0');
    sendMsg(payload_size, sockd, msg_to_send);

    msg_to_send.assign(msg_to_send.size(), 0);
    
    return true;

}   // send (nonce, ecdh_key, cert, dig_sign)


//HERE
/*
bool Server::receiveSign(int sockd, string username, vector<unsigned char>& recv_buf) {
    // receive and verify client digital signature 
    cout << "server->receiveSign" << endl;
    //vector<unsigned char> recv_buf;
    int payload_size = receiveMsg(sockd, recv_buf);
    if(payload_size <= 0) {
        cerr << "Error on Receive -> close connection with client on socket: " << sockd << endl;
        close(sockd);
        pthread_exit(NULL);
        return false;
    }

    uint16_t opcode = *(unsigned short*)recv_buf.data();  //recv_buf.at(0);
    if(opcode != LOGIN) {
        handleErrors("Opcode error", sockd);
        return false;
    }
    recv_buf.erase(recv_buf.begin(), recv_buf.begin() + OPCODE_SIZE);
    if(recv_buf.size() <= NONCE_SIZE) {
        handleErrors("Received msg size error", sockd);
        return false;
    }

    pthread_mutex_lock(&mutex);
    if(connectedClient.find(username) == connectedClient.end())
        handleErrors("username not found", sockd);
        
    UserInfo usr = connectedClient.at(username);
    pthread_mutex_unlock(&mutex);

    vector<unsigned char> server_nonce;
    server_nonce.insert(server_nonce.begin(), recv_buf.begin(), recv_buf.begin() + NONCE_SIZE);
    if(!usr.client_session->checkNonce(server_nonce.data())) {
        sendErrorMsg(sockd, "Received nonce not verified");
        
        pthread_mutex_lock(&mutex);
        connectedClient.erase(username);
        pthread_mutex_unlock(&mutex);
        handleErrors("Received server nonce not verified", sockd);
    }


    return true;
}
*/

void Server::requestFileList() {

}

void Server::sendFileList() {

}

void Server::logoutClient(int sockd) {

}

void Server::sendErrorMsg(int sockd, string &errorMsg) {
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

// TODO
void Server::uploadFile() {

}

void Server::downloadFile() {

}

void Server::renameFile() {

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
    cout<< "exit1 \n";
    pthread_exit(NULL);
    return NULL;
}