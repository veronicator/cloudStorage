#include "server.h"

UserInfo::UserInfo(int sd, string name)
{
    sockd = sd;
    username = name;

    client_session = new Session();
}

UserInfo::~UserInfo()
{
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

Server::Server()
{
    if(pthread_mutex_init(&mutex_client_list, NULL) != 0)
    {
        cerr << "mutex init failed " << endl;
        exit(1);
    }
    if(!createSrvSocket())
    {
        perror("Socket creation error");
        exit(1);
    }
}

bool Server::createSrvSocket()
{
    cout << "createServerSocket" << endl;
    
    if((listener_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) // socket TCP
    {
        return false;
    }

    // set reuse socket
    int yes = 1;
    if(setsockopt(listener_sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0)
    {
        cerr << "set reuse socket error" << endl;
        return false;
    }

    // creation server address
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(SRV_PORT);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(listener_sd, (sockaddr*)&my_addr, sizeof(my_addr)) != 0)
    {
        cerr << "Bind error" << endl;
        return false;
    }
    //cout << "bind\n";
    if(listen(listener_sd, MAX_CLIENTS) != 0)
    {
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

void Server::client_thread_code(int sd) {
    cout << "client thread code -> run()\n";
    cout << "thread socket " << sd << endl;
    /*
    pthread_mutex_lock(&mutex);
    if(connectedClient.find(sd) == connectedClient.end()) {
        handleErrors("socket descriptor not found");
    }
    UserInfo usr = connectedClient.at(sd);
    pthread_mutex_unlock(&mutex);
    */
    vector<unsigned char> recv_buf;
    int payload_size;
    int received_size = receiveMsg(sd, recv_buf);

    uint16_t opcode = *(unsigned short*)recv_buf.data();  //recv_buf.at(0);
    if(opcode != LOGIN) {
        handleErrors("Opcode error", sd);
        return;
    }
    recv_buf.erase(recv_buf.begin(), recv_buf.begin() + OPCODE_SIZE);
    if(recv_buf.size() <= NONCE_SIZE) {
        handleErrors("Received msg size error", sd);
    }
    vector<unsigned char> client_nonce;
    client_nonce.insert(client_nonce.begin(), recv_buf.begin(), recv_buf.begin() + NONCE_SIZE);
    string username = string(recv_buf.begin() + NONCE_SIZE, recv_buf.end());
    cout << "user " << username << endl;

    recv_buf.clear();


    pthread_mutex_lock(&mutex);     // mutex on client list
    // check if user already present on server
    if(connectedClient.find(username) != connectedClient.end()) {
        string errorMsg = "User already connected";
        //cerr << errorMsg << endl;

        // inviare mess errore al client
        int payload_size = OPCODE_SIZE + errorMsg.size();
        vector<unsigned char> send_buf(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
        memcpy(send_buf.data(), &payload_size, NUMERIC_FIELD_SIZE);
        uint16_t op = ERROR;
        memcpy(send_buf.data() + NUMERIC_FIELD_SIZE, &op, OPCODE_SIZE);
        send_buf.insert(send_buf.end(), errorMsg.begin(), errorMsg.end());
        
        sendMsg(payload_size, sd, send_buf);
        
        handleErrors(errorMsg.c_str(), sd);

        return;
    }

    UserInfo new_usr(sd, username);
    //connectedClient.insert(pair<int, UserInfo>(new_sd, new_usr));
    connectedClient.insert({username, new_usr});
    cout << "connected size " << connectedClient.size() << endl;

/*    if(connectedClient.find(username) == connectedClient.end())
        handleErrors("username not found", sd);
       
    UserInfo usr = connectedClient.at(username);
*/ 
    pthread_mutex_unlock(&mutex);

    sendCertSign(client_nonce, username, sd);
    
    receiveSign(sd, username, recv_buf);
    
    /* 
    verifica firma
    invia lista utenti online
    -> end authentication */

    pthread_mutex_lock(&mutex);
    connectedClient.erase(sockd);
    pthread_mutex_unlock(&mutex);
    
}


/********************************************************************/

/**
 * send a message through the specific socket
 * @payload_size: body lenght of the message to send
 * @sockd: socket descriptor through which send the message to the corresponding client
 * @send_buf: sending buffer containing the message to send, associated to a specific client
 * @return: 1 on success, 0 or -1 on error
 */
int Server::sendMsg(int payload_size, int sockd, vector<unsigned char>& send_buf) {
    cout << payload_size << " sendMsg: payload size" << endl;
    if(payload_size > MAX_BUF_SIZE - NUMERIC_FIELD_SIZE) {
        cerr << "Message to send too big" << endl;
        send_buf.assign(send_buf.size(), '0');
        send_buf.clear();    //fill('0');
        //close(sockd);
        return -1;
        //handleErrors("Message to send too big", sockd);
    }

    payload_size += NUMERIC_FIELD_SIZE;
    if(send(sockd, send_buf.data(), payload_size, 0) < payload_size) {
        perror("Socker error: send message failed");
        send_buf.assign(send_buf.size(), '0');
        send_buf.clear();    //fill('0');
        //close(sockd);
        return -1;
        //handleErrors("Send error", sockd);
    }

    send_buf.assign(send_buf.size(), '0');
    send_buf.clear();
//    memset(send_buf.data(), 0, MAX_BUF_SIZE);
    return 1;
}

/**
 * receive message from a client, associated to a specific socket 
 * @sockd: socket descriptor through which the client is connected
 * @recv_buf: vector buffer where save the message received
 * @return: return the payload length of the received message, or 0 or -1 on error
*/
long Server::receiveMsg(int sockd, vector<unsigned char>& recv_buf) {

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

    // TODO: trovare soluzione alternativa invece di cancellare gli elementi dal vector ?
    // remove the first field of the message, containing the payload size ?
    recv_buf.insert(recv_buf.begin(), receiver.begin(), receiver.begin() + msg_size);
    receiver.fill('0');
    //recv_buf.erase(recv_buf.begin(), recv_buf.begin() + NUMERIC_FIELD_SIZE);
    cout << "recv size buf: " << recv_buf.size() << endl;

    return msg_size;
}


/********************************************************************/

bool Server::authenticateClient(int sockd) {

    return true;
}


/********************************************************************/

void Server::sendCertSign(vector<unsigned char> clt_nonce, string username, int sockd) {
    cout << "server->sendCertSign" << endl;
    // recupera certificato, serializza cert, copia nel buffer, genera nonce, genera ECDH key, firma, invia
    // retrieve user structure
    pthread_mutex_lock(&mutex);
    if(connectedClient.find(username) == connectedClient.end())
        handleErrors("username not found", sockd);
        
    UserInfo usr = connectedClient.at(username);
    pthread_mutex_unlock(&mutex);

    // retrieve server private key
    EVP_PKEY* srv_priv_k;
    usr.client_session->retrievePrivKey("./server/Server_key.pem", srv_priv_k);

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
    usr.client_session->generateNonce();
    usr.client_session->generateECDHKey();
    unsigned char* ECDH_srv_pub_key = NULL;
    uint32_t ECDH_srv_key_size = usr.client_session->serializePubKey(usr.client_session->ECDH_myKey, ECDH_srv_pub_key);
    BIO_dump_fp(stdout, (const char*)ECDH_srv_pub_key, ECDH_srv_key_size);
    // cout << "after serialize pub" << endl;
    // prepare message to sign
    array<unsigned char, MAX_BUF_SIZE> buffer;  // support array
    vector<unsigned char> msg_to_send;      // buffer to sign and send
    //vector<unsigned char> send_buf;

    msg_to_send.insert(msg_to_send.begin(), clt_nonce.begin(), clt_nonce.end());
    cout << "insert 1\n";
    // todo: fix
    //msg_to_send.insert(msg_to_send.end(),usr.client_session->nonce.begin(), usr.client_session->nonce.end());
    cout << "insert 2" << endl;
/*
    memcpy(buffer.data(), cert_buf, cert_size);
    cout << "memcpy 1" << endl;
    msg_to_send.insert(msg_to_send.end(), buffer.begin(), buffer.begin() + cert_size);
    cout << "insert 3" << endl;
    buffer.fill('0');
    cout << "fill 1\n";
    */
    memcpy(buffer.data(), ECDH_srv_pub_key, ECDH_srv_key_size);
    cout << "memcpy 2" << endl;
    msg_to_send.insert(msg_to_send.end(), buffer.begin(), buffer.begin() + ECDH_srv_key_size);
    cout << " insert 4" << endl;
    buffer.fill('0');

    unsigned char* signed_msg = NULL;
    int signed_msg_len = usr.client_session->signMsg(msg_to_send.data(), msg_to_send.size(), srv_priv_k, signed_msg);

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
    
}   // send (nonce, ecdh_key, cert, dig_sign)

bool Server::receiveSign(int sd, string username, vector<unsigned char>& recv_buf) {
    /* receive and verify client digital signature */
    cout << "server->receiveSign" << endl;
    //vector<unsigned char> recv_buf;
    int payload_size = receiveMsg(sd, recv_buf);

    uint16_t opcode = *(unsigned short*)recv_buf.data();  //recv_buf.at(0);
    if(opcode != LOGIN) {
        handleErrors("Opcode error", sd);
        return false;
    }
    recv_buf.erase(recv_buf.begin(), recv_buf.begin() + OPCODE_SIZE);
    if(recv_buf.size() <= NONCE_SIZE) {
        handleErrors("Received msg size error", sd);
        return false;
    }

    pthread_mutex_lock(&mutex);
    if(connectedClient.find(username) == connectedClient.end())
        handleErrors("username not found", sd);
        
    UserInfo usr = connectedClient.at(username);
    pthread_mutex_unlock(&mutex);

    vector<unsigned char> server_nonce;
    server_nonce.insert(server_nonce.begin(), recv_buf.begin(), recv_buf.begin() + NONCE_SIZE);
    if(!usr.client_session->checkNonce(server_nonce.data())) {
        sendErrorMsg(sd, "Received nonce not verified");
        
        pthread_mutex_lock(&mutex);
        connectedClient.erase(username);
        pthread_mutex_unlock(&mutex);
        handleErrors("Received server nonce not verified", sd);
    }


    return true;
}
/*
bool Server::authenticationClient(int sd) {
    cout << "server->authenticationClient" << endl;
    vector<unsigned char> recv_buf;
    int payload_size;
    int received_size = receiveMsg(payload_size, sd, recv_buf);

    uint16_t opcode = *(unsigned short*)recv_buf.data();  //recv_buf.at(0);
    if(opcode != LOGIN) {
        handleErrors("Opcode error", sd);
        return false;
    }
    recv_buf.erase(recv_buf.begin(), recv_buf.begin() + OPCODE_SIZE);
    if(recv_buf.size() <= NONCE_SIZE) {
        handleErrors("Received msg size error", sd);
        return false;
    }
    vector<unsigned char> client_nonce;
    client_nonce.insert(client_nonce.begin(), recv_buf.begin(), recv_buf.begin() + NONCE_SIZE);
    string username = string(recv_buf.begin() + NONCE_SIZE, recv_buf.end());
    cout << "user " << username << endl;


    pthread_mutex_lock(&mutex);     // mutex on client list
    // check if user already present on server
    if(connectedClient.find(username) != connectedClient.end()) {
        string errorMsg = "User already connected";
        //cerr << errorMsg << endl;

        // inviare mess errore al client
        int payload_size = OPCODE_SIZE + errorMsg.size();
        vector<unsigned char> send_buf(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
        memcpy(send_buf.data(), &payload_size, NUMERIC_FIELD_SIZE);
        uint16_t op = ERROR;
        memcpy(send_buf.data() + NUMERIC_FIELD_SIZE, &op, OPCODE_SIZE);
        send_buf.insert(send_buf.end(), errorMsg.begin(), errorMsg.end());
        
        sendMsg(payload_size, sd, send_buf);
        
        handleErrors(errorMsg.c_str(), sd);

        return false;
    }

    UserInfo new_usr(sd, username);
    //connectedClient.insert(pair<int, UserInfo>(new_sd, new_usr));
    connectedClient.insert({username, new_usr});
    cout << "connected size " << connectedClient.size() << endl;
    
    pthread_mutex_unlock(&mutex);

    sendCertSign(client_nonce, username, sd);

    return true;
}  // call session.generatenonce & sendMsg
*/

void Server::requestFileList() {

}

void Server::sendFileList() {

}

void Server::logoutClient(int sockd) {

}

void Server::sendErrorMsg(int sd, string errorMsg) {
        //cerr << errorMsg << endl;

        // inviare mess errore al client
        int payload_size = OPCODE_SIZE + errorMsg.size();
        vector<unsigned char> send_buf(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
        memcpy(send_buf.data(), &payload_size, NUMERIC_FIELD_SIZE);
        uint16_t op = ERROR;
        memcpy(send_buf.data() + NUMERIC_FIELD_SIZE, &op, OPCODE_SIZE);
        send_buf.insert(send_buf.end(), errorMsg.begin(), errorMsg.end());
        
        sendMsg(payload_size, sd, send_buf);

}
/*
void Server::joinThread() {
    while(!threads.empty()) {
        threads.front().join();
        threads.pop_front();
    }
}*/


//---------------------------------------------------------

int
Server::sendMsgChunks(UserInfo* ui, string filename)
{
    string path = FILE_PATH_SV + ui->username + "/" + filename;                         
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

    int ret;                                                                            //bytes read by the fread function
    size_t tot_chunks = ceil((float)buffer.st_size / FRAGM_SIZE);                       //total number of chunks needed form the upload
    size_t to_send;                                                                     //number of byte to send in the specific msg
    uint32_t payload_size, payload_size_n;                                              //size of the msg payload both in host and network format    
    vector<unsigned char> aad;                                                          //aad of the msg
    array<unsigned char, FRAGM_SIZE> frag_buffer;                                       //msg to be encrypted
    array<unsigned char, MAX_BUF_SIZE> cyphertext;                                      //encrypted text
    
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
            ui->client_session->createAAD(aad.data(), END_OP);                        //last chunk -> END_OP opcode sent to server
        }
        else
        {
            to_send = FRAGM_SIZE;
            ui->client_session->createAAD(aad.data(), DOWNLOAD);                        //intermediate chunks
        }

        ret = fread(frag_buffer.data(), sizeof(char), to_send, file);

        if(ferror(file) != 0 || ret != to_send)
        {
            cerr<<"ERROR while reading file"<<endl;

            aad.assign(aad.size(), '0');
            aad.clear();
            frag_buffer.fill('0');

            return -1;
        }

        payload_size = ui->client_session->encryptMsg(frag_buffer.data(), frag_buffer.size(), aad.data(), aad.size(), cyphertext.data());
        payload_size_n = htonl(payload_size);

        //=== Managemetn Buffer ===
        aad.assign(aad.size(), '0');
        aad.clear();
        frag_buffer.fill('0');

        memcpy(&payload_size_n, ui->send_buffer.data(), NUMERIC_FIELD_SIZE);
        ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, cyphertext.begin(), cyphertext.begin() + payload_size);

        //=== Managemetn Buffer ===   
        cyphertext.fill('0');
        ui->send_buffer.assign(ui->send_buffer.size(), '0');
        ui->send_buffer.clear();
        ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
        

        if(sendMsg(payload_size, ui->sockd, ui->send_buffer) != 1)
        {
            cerr<<"Error during send phase (C->S) | Upload Chunk Phase (chunk num: "<<i<<")"<<endl;

            //=== Cleaining ===
            aad.assign(aad.size(), '0');
            aad.clear();
            frag_buffer.fill('0');
            cyphertext.fill('0');

            return -1;
        }

        print_progress_bar(tot_chunks, i);
    }

    //=== Cleaining ===
    aad.assign(aad.size(), '0');
    aad.clear();
    frag_buffer.fill('0');
    cyphertext.fill('0');
    
    return 1;
}

// TODO
void Server::uploadFile() {

}

void Server::renameFile() {

}


int
Server::downloadFile(int sockd, vector<unsigned char> plaintext)
{
    string filename;
    uint32_t payload_size, payload_size_n;
    string ack_msg;
    vector<unsigned char> aad;
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

    if(checkFileExist(filename, ui->username, FILE_PATH_SV) != 0)
    {
        cerr<<"Error: this file is not present in the folder"<<endl;
        ack_msg = "File not present in the cloud";

        file_ok = false;
    }

    if(file_ok)
    {   ack_msg = MESSAGE_OK; }
}

int
Server::deleteFile(int sockd, vector<unsigned char> plaintext)
{
    string filename;
    uint32_t payload_size, payload_size_n;
    string ack_msg;
    vector<unsigned char> aad;
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

    if(checkFileExist(filename, ui->username, FILE_PATH_SV) != 0)
    {
        cerr<<"Error: this file is not present in the folder"<<endl;
        ack_msg = "File not present in the cloud";

        file_ok = false;
    }

    if(file_ok)
    {   ack_msg = MESSAGE_OK; }

    //=== Preparing Data Sending and Encryption ===
    plaintext.insert(plaintext.begin(), ack_msg.begin(), ack_msg.end());

    ui->client_session->createAAD(aad.data(), DELETE_REQ);
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), aad.size(), cyphertext.data());
    payload_size_n = htonl(payload_size);
    
    ui->send_buffer.assign(ui->send_buffer.size(), '0');
    ui->send_buffer.clear();
    ui->send_buffer.resize(NUMERIC_FIELD_SIZE);
    
    memcpy(ui->send_buffer.data(), &payload_size_n, NUMERIC_FIELD_SIZE);
    ui->send_buffer.insert(ui->send_buffer.begin() + NUMERIC_FIELD_SIZE, cyphertext.begin(), cyphertext.begin() + payload_size);

    if(sendMsg(payload_size, sockd, ui->send_buffer) != -1 || !file_ok)
    {
        cerr<<"Error during sending DELETE_REQUEST_RESPONSE phase (S->C)"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }

// _END_(1))-------------- [ M1: SEND_CONFIRMATION_DELETE_REQUEST_TO_CLIENT ] --------------


// _BEGIN_(2)-------------- [ M2: RECEIVE_CHOICE_OPERATION_FROM_CLIENT ] --------------

    int aad_len; uint16_t opcode;
    uint64_t received_len;  //legnht of the message received from the client
    uint32_t plaintext_len;
    string user_choice, final_msg;  //final_msg: message of successful cancellation

    // === Reuse of vectors declared at the beginning ===
    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    received_len = receiveMsg(sockd, ui->recv_buffer);
    if(received_len == 0 || received_len == -1)
    {
        cout<<"Error during receive phase (C->S)"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }

    plaintext_len = ui->client_session->decryptMsg(ui->recv_buffer.data(), received_len,
                                                aad.data(), aad_len, plaintext.data());

    //Opcode sent by the client, must be checked before proceeding (Lies into aad)
    opcode = ntohs(*(uint16_t*)(aad.data() + NUMERIC_FIELD_SIZE));    
    if(opcode != DELETE_CONFIRM)
    {
        cout<<"Error! Exiting DELETE_OPERATION phase"<<endl;

        // === Cleaning ===
        plaintext.assign(plaintext.size(), '0');
        plaintext.clear();
        aad.assign(aad.size(), '0');
        aad.clear();

        return -1;
    }

    user_choice = ((char*)plaintext.data());

// _END_(2)-------------- [ M2: RECEIVE_CHOICE_OPERATION_FROM_CLIENT ] --------------


// _BEGIN_(3)-------------- [ M3: SEND_RESPONSE_OF_THE_OPERATION_TO_CLIENT ] --------------

    if(user_choice == "Y" || user_choice == "y")
    {
        cout<<"\n\t~ The file *( "<< filename << " )* is going to be deleted. ~\n\n"<<endl;

        if(removeFile(filename, ui->username, FILE_PATH_SV) == -1)
        {
            cout << "\n\t --- Error during Deleting file ---\n" << endl; 
        }

        final_msg = "File Deleted Successfully";
    }

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();
    cyphertext.fill('0');

    // === Reuse of vectors declared at the beginning ===
    aad.resize(NUMERIC_FIELD_SIZE + OPCODE_SIZE);
    plaintext.resize(MAX_BUF_SIZE);

    // === Preparing Data Sending and Encryption ===    
    plaintext.insert(plaintext.begin(), final_msg.begin(), final_msg.end());

    ui->client_session->createAAD(aad.data(), END_OP);
    payload_size = ui->client_session->encryptMsg(plaintext.data(), plaintext.size(), aad.data(), aad.size(), cyphertext.data());
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
        aad.assign(aad.size(), '0');
        aad.clear();
        cyphertext.fill('0');

        return -1;
    }                                                

// _END_(3)-------------- [ M3: SEND_RESPONSE_OF_THE_OPERATION_TO_CLIENT ] --------------

    // === Cleaning ===
    plaintext.assign(plaintext.size(), '0');
    plaintext.clear();
    aad.assign(aad.size(), '0');
    aad.clear();
    cyphertext.fill('0');

    return 1; //Successful_State
}


/********************************************/

ThreadArgs::ThreadArgs(Server* serv, int new_sockd)
{
    if(!serv)
    {
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
    serv->client_thread_code(sockd);
    cout<< "exit1 \n";
    pthread_exit(NULL);
    return NULL;
}