#include "../utils/security_utils.h"

class Client {
    string username;
    EVP_PKEY *my_priv_key;  // togliere?
    Session *server_session;
    Session *client_session;

    unsigned char *send_buffer;
    unsigned char *recv_buffer;

    /****************************/
    // socket
    int sd; // socket descriptor
    sockaddr_in sv_addr;

    void createSocket(string srv_ip);
    /****************************/

    bool verifyCert(unsigned char* buffer_cert, long cert_size, EVP_PKEY*& srv_pubK); // verify certificate -> build store -> load cert&crl -> extract pubK
    void buildStore(X509*& ca_cert, X509_CRL*& crl, X509_STORE*& new_store);

    public:
        Client(string username, string srv_ip);
        void sendMsg(int msg_dim);       //dopo invio: deallocare buffer
        int receiveMsg(int& payload_size);    // restituisce lunghezza totale messaggio ricevuto, msg_size
        
        void sendUsername();
        bool receiveCertSign(unsigned char*& srv_nonce);    // receive (nonce, ecdh_key, cert, dig_sign), deserialize and verify server cert and digital signature
        void sendSign(unsigned char* srv_nonce);
        bool authentication();  // call session.generatenonce & sendMsg
        void showCommands();
        bool handlerCommand(string& command);
        void requestFileList();
        void receiveFileList();
        void logout();  // dealloca tutto ed esce

        // TODO: modificare come serve 
        // (li scrivo solo per evitare conflitti su git, ci sono anche le definizioni nel file .cpp)
        void uploadFile();
        void downloadFile();
        void renameFile();
        void deleteFile();

        void sendErrorMsg(string errorMsg);

    //test
};