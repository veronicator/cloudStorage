#include "../utils/security_utils.h"

#define path_file "./server/userStorage/"

// TODO

struct UserInfo {
    string username;    // client username
    int sockd;
    Session* client_session;
    vector<unsigned char> send_buffer;
    vector<unsigned char> recv_buffer;

    UserInfo(int sd, string name);
    ~UserInfo();

    void cleanup();
};
    

class Server {
    //static Server* server;

    // vector<Session> activeSessions;
    //todo: fare un unica mappa <int sockID, UserInfo> ?
    unordered_map<int, UserInfo*> connectedClient;    // client sockd, session
    //unordered_map<string, int> socketClient;      // client username, socket descriptor -> to find if a client is already connected and what is his sockd
    //map<int, UserInfo> connectedClient;     // client_socket descriptor, userInfo struct
    //unordered_map<string, UserInfo> activeChats;  // client username, data about chat
    // vector/list/map di int socket e username ?
    EVP_PKEY *priv_key;
    
    /***********************/
    // singlenton
    //Server();

    /***********************/
    // socket 
    int listener_sd;    // socket di ascolto
    sockaddr_in my_addr, cl_addr;
    socklen_t addr_len;

    bool createSrvSocket();
    
    /****************************************************/
    //pthread_t client_thread;
    pthread_mutex_t mutex_client_list;
    //pthread_mutex_t mutex_socket_list;

    //list<thread> threads;
    //std::mutex mtx;


    /****************************************************/
    
    bool searchUserExist(string usr_name);
    
    /****************************************************/

    int sendMsg(uint32_t payload_size, int sockd, vector<unsigned char> &send_buffer);       //dopo invio: deallocare buffer
    long receiveMsg(int sockd, vector<unsigned char> &recv_buffer);    // restituisce lunghezza totale messaggio ricevuto, msg_size

    EVP_PKEY* getPeerKey(string username);

    bool receiveUsername(int sockd, vector<unsigned char> &clt_nonce);
    bool sendCertSign(int sockd, vector<unsigned char> &clt_nonce, array<unsigned char, NONCE_SIZE> &srv_nonce);    // send (nonce, ecdh_key, cert, dig_sign), deserialize and verify server cert and digital signature
    bool receiveSign(int sockd, array<unsigned char, NONCE_SIZE> &srv_nonce);
    bool authenticationClient(int sockd);  // call session.generatenonce & sendMsg
 
    int receiveMsgChunks(UserInfo* ui, uint64_t filedimension, string filename);
    int sendMsgChunks(UserInfo* ui, string filename);
    
    int changeName(string old_filename, string new_filename, string username);
    int uploadFile(int sockd, vector<unsigned char> plaintext, uint32_t pt_len);
    int downloadFile(int sockd, vector<unsigned char> plaintext);
    int renameFile(int sockd, vector<unsigned char> plaintext, uint32_t pt_len);
    int deleteFile(int sockd, vector<unsigned char> plaintext);

    int sendFileList(int sockd);
    void logoutClient(int sockd); 

    void sendErrorMsg(int sockd, string errorMsg);

    
    /****************************************************/

    public:
        Server();

        // socket
        int acceptConnection();
        int getListener();
        //void* client_thread_code(void *arg);  // friend?
        void run_thread(int sd);

        //void joinThread();

    //test
};

struct ThreadArgs {
    Server* server;
    int sockd;

    ThreadArgs(Server* serv, int new_sockd);
};

void* client_thread_code(void *arg);
//void joinThread();