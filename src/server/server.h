#include "../utils/security_utils.h"

#define path_file "./server/"

// TODO

struct UserInfo {
    string username;    // client username
    int sockd;
    //bool available = false; // true: when online and there is no active chat, false otherwise
    Session* client_session;
    //unsigned char *send_buffer = nullptr;
    //unsigned char *recv_buffer = nullptr;
    vector<unsigned char> send_buffer;
    vector<unsigned char> recv_buffer;

    UserInfo(int sd, string name);
    //UserInfo();
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

    void createSrvSocket();
    
    /***********************/

    public:
        Server();
        //static Server* getServer();

        //pthread_t client_thread;
        pthread_mutex_t mutex_client_list;
        //pthread_mutex_t mutex_socket_list;

        //list<thread> threads;
        std::mutex mtx;


        // socket
        int acceptConnection();
        int getListener();
        //void* client_thread_code(void *arg);  // friend?
        void client_thread_code(int sd);

        int sendMsg(int payload_size, int sockd, vector<unsigned char> &send_buffer);       //dopo invio: deallocare buffer
        long receiveMsg(int sockd, vector<unsigned char> &recv_buffer);    // restituisce lunghezza totale messaggio ricevuto, msg_size

        bool receiveUsername(int sockd);
        bool sendCertSign(vector<unsigned char> &clt_nonce, string &username, int sockd);    // send (nonce, ecdh_key, cert, dig_sign), deserialize and verify server cert and digital signature
        bool receiveSign(int sd, string &username, vector<unsigned char> &recv_buf);
        bool authenticationClient(int sockd);  // call session.generatenonce & sendMsg
        
        void requestFileList();
        void sendFileList();
        void logoutClient(int sockd); 

        void sendErrorMsg(int sd, string &errorMsg);

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