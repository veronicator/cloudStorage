#include "../utils/security_utils.h"

#define FILE_PATH_SRV "./server/userStorage/"
#define KEY_PATH_SRV "./server/userKeys/"
#define SERV_CERT_PATH "./server/Server_cert.pem"

struct UserInfo {
    string username;    // client username
    int sockd;
    Session* client_session;
    vector<unsigned char> send_buffer;
    vector<unsigned char> recv_buffer;

    UserInfo(int sd, string name);
    ~UserInfo();

};
    

class Server {

    unordered_map<int, UserInfo*> connectedClient;    // client socket descriptor, user data

    EVP_PKEY *priv_key;

    /***********************/
    // socket 
    int listener_sd;    // socket di ascolto
    sockaddr_in my_addr, cl_addr;
    socklen_t addr_len;

    bool createSrvSocket();
    
    /****************************************************/

    pthread_mutex_t mutex_client_list;

    /****************************************************/
    
    int sendMsg(uint32_t payload_size, int sockd, vector<unsigned char> &send_buffer);
    long receiveMsg(int sockd, vector<unsigned char> &recv_buffer);    // restituisce lunghezza totale messaggio ricevuto, msg_size

    EVP_PKEY* getPeerKey(string username);

    bool receiveUsername(int sockd, vector<unsigned char> &clt_nonce);
    bool sendCertSign(int sockd, vector<unsigned char> &clt_nonce, array<unsigned char, NONCE_SIZE> &srv_nonce);    // send (nonce, ecdh_key, cert, dig_sign), deserialize and verify server cert and digital signature
    bool receiveSign(int sockd, array<unsigned char, NONCE_SIZE> &srv_nonce);
    bool authenticationClient(int sockd);  // call session.generatenonce & sendMsg
 
    int receiveMsgChunks(UserInfo* ui, uint64_t filedimension, string canon_path);
    int sendMsgChunks(UserInfo* ui, string canon_path);
    
    int changeName(string old_filename, string new_filename, string username);
    int uploadFile(int sockd, vector<unsigned char> plaintext, uint32_t pt_len);
    int downloadFile(int sockd, vector<unsigned char> plaintext);
    int renameFile(int sockd, vector<unsigned char> plaintext, uint32_t pt_len);
    int deleteFile(int sockd, vector<unsigned char> plaintext, uint32_t pt_len);

    int sendFileList(int sockd);
    void logoutClient(int sockd); 

    /****************************************************/

    public:
        Server();

        // socket
        int acceptConnection();
        int getListener();
        void run_thread(int sd);
};

/** data structure to manage the arguments needed by a thread*/
struct ThreadArgs {
    Server* server;
    int sockd;

    ThreadArgs(Server* serv, int new_sockd);
};

void* client_thread_code(void *arg);