#include "../utils/security_utils.h"

class Client {
    string username;
    //EVP_PKEY *my_priv_key;  // togliere?
    Session *active_session;

    //unsigned char *send_buffer;
    //unsigned char *recv_buffer;
    vector<unsigned char> send_buffer;
    vector<unsigned char> recv_buffer;

    /********* socket *********/
    int sd; // socket descriptor
    sockaddr_in sv_addr;

    bool createSocket(string srv_ip);
    /****************************/

    /***** utility methods *****/

    // new sed/receive
    int sendMsg(uint32_t payload_size);
    long receiveMsg();


    //void sendErrorMsg(string errorMsg);
    
    bool verifyCert(unsigned char* buffer_cert, long cert_size, EVP_PKEY*& srv_pubK); // verify certificate -> build store -> load cert&crl -> extract pubK
    bool buildStore(X509*& ca_cert, X509_CRL*& crl, X509_STORE*& new_store);


    // methods invoked during the authentication phase -> never called from outside class -> can be private
    int sendUsername(array<unsigned char, NONCE_SIZE> &client_nonce);
    bool receiveCertSign(array<unsigned char, NONCE_SIZE> &client_nonce, vector<unsigned char> &srv_nonce);    // receive (nonce, ecdh_key, cert, dig_sign), deserialize and verify server cert and digital signature
    int sendSign(vector<unsigned char> &srv_nonce, EVP_PKEY *&priv_k);

    // methods invoked by handlerCommand method -> only from inside -> can be private
    int requestFileList();
    int receiveFileList();
    void logout();  // dealloca tutto ed esce

    int uploadFile();
    uint32_t sendMsgChunks(string filename);
    int receiveMsgChunks( uint32_t filedimension, string filename);
    int downloadFile();
    int renameFile();
    int deleteFile();


    public:
        Client(string username, string srv_ip);
        ~Client();

        bool authentication();  // call session.generatenonce, sendMsg, receive
        void showCommands();
        bool handlerCommand(string& command);
        
};