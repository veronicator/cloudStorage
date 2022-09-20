#include "../utils/security_utils.h"

#define path_file "./server/"

// TODO

struct UserInfo {
    string username;    // client username
    int sockd;
    bool available = false; // true: when online and there is no active chat, false otherwise
    Session* client_session;
    unsigned char *send_buffer = nullptr;
    unsigned char *recv_buffer = nullptr;
    //vector<unsigned char> send_buffer;
    //vector<unsigned char> recv_buffer;

    UserInfo(int sd, string name);
    //UserInfo();
};

class Server {
    //static Server* server;

    // vector<Session> activeSessions;
    map<string, UserInfo> connectedClient;    // client username, session
    map<int, string> socketClient;      //socket descriptor, client username        // togliere sockd da UserInfo ?
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

    void createSrvSocket();
    
    /***********************/

    public:
        Server();
        //static Server* getServer();

        //pthread_t client_thread;
        pthread_mutex_t mutex;

        //list<thread> threads;
        std::mutex mtx;


        // socket
        int acceptConnection();
        int getListener();
        //void* client_thread_code(void *arg);  // friend?
        void client_thread_code(int sd);     

        void sendMsg(int payload_size, int sockd, vector<unsigned char>& send_buf);       //dopo invio: deallocare buffer
        int receiveMsg(int& payload_size, int sockd, vector<unsigned char>& recv_buf);    // restituisce lunghezza totale messaggio ricevuto, msg_size
        void receiveUsername(int sockd);
        void sendCertSign(vector<unsigned char> clt_nonce, string username, int sockd);    // send (nonce, ecdh_key, cert, dig_sign), deserialize and verify server cert and digital signature
        bool receiveSign(int sd, string username, vector<unsigned char>& recv_buf);
        bool authenticationClient(int sd);  // call session.generatenonce & sendMsg
        
        void requestFileList();
        void sendFileList();
        void logoutClient(int sockd); 

        void sendErrorMsg(int sd, string errorMsg);

        void joinThread();

        // TODO: modificare come serve 
        // (li scrivo solo per evitare conflitti su git, ci sono anche le definizioni nel file .cpp)
        void uploadFile();
        void downloadFile();
        void renameFile();
        void deleteFile();



    //test
};

struct ThreadArgs {
    Server* server;
    int sockd;

    ThreadArgs(Server* serv, int new_sockd);
};

void* client_thread_code(void *arg);
void joinThread();