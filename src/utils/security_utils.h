#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string>
#include <string.h>
#include <limits.h>
#include <iterator>
#include <vector>
#include <array>
#include <map>
#include <list>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <arpa/inet.h>  // htonl/ntohl
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <regex.h>
#include <regex>
#include <cmath>
#include <filesystem>
#include <experimental/filesystem>
#include "symbols.h"

using namespace std;
namespace fs = std::experimental::filesystem;

void handleErrors();

void handleErrors(const char *error);

void handleErrors(const char *error, int sockd);

void terminate();   // TODO: dealloca tutto e termina in caso di errore

void incrementCounter(uint32_t& counter);

/*
void generateRandomValue(unsigned char* new_value, int value_size) {
    if(RAND_poll() != 1) { cerr << "Error in RAND_poll\n"; exit(1); }
    if(RAND_bytes((unsigned char*)&new_value[0], value_size) != 1) { cerr << "Error in RAND_bytes\n"; exit(1); }
}
*/
//void readUsername(string& usr);

void readInput(string& input, const int MAX_SIZE, string);  // read MAX_SIZE charachters from standard input and put them in "input" string

void readFilenameInput(string& input, string msg);  

uint64_t searchFile(string filename, string username);

bool searchDir(string dir_name);

void clear_vec(vector<unsigned char>& v);
void clear_arr(unsigned char* arr, int arr_len);
void clear_three_vec(vector<unsigned char>& v1, vector<unsigned char>& v2, vector<unsigned char>& v3);
void clear_vec_array(vector<unsigned char>& v1, unsigned char* arr, int arr_len);
void clear_two_vec(vector<unsigned char>& v1, vector<unsigned char>& v2);

//int buffer_copy(unsigned char*& dest, unsigned char* src, int len);


class Session {
    unsigned char* session_key;
    uint32_t send_counter = 1;
    uint32_t rcv_counter = 0;


    void incrementCounter(uint32_t& counter);
    int computeSessionKey(unsigned char* secret, int slen);  //shared secret -> session key

    int generateRandomValue(unsigned char* new_value, int value_size);
    
    public:
        EVP_PKEY* ECDH_myKey = NULL;    // ephimeral 
        EVP_PKEY* ECDH_peerKey = NULL;  // ephimeral
        //unsigned char* ECDH_myPubKey;  // serialized ecdh public key, to send
        //unsigned char* iv;
        //array<unsigned char, NONCE_SIZE> nonce;

        Session() {};
        ~Session(); //deallocare tutti i vari buffer utilizzati: session_key ecc

        // Session utils
        uint32_t createAAD(unsigned char* aad, uint16_t opcode); // return aad_len
        // void readInput(string& input, const int MAX_SIZE, string msg = "");  // read MAX_SIZE charachters from standard input and put in "input" string

        EVP_PKEY* get_peerKey();

        EVP_PKEY* retrievePrivKey(string path);  // retrieve its own private key from pem file and return it
        int computeHash(unsigned char* msg, int len, unsigned char*& msgDigest);
        long signMsg(unsigned char* msg_to_sign, unsigned int msg_to_sign_len, EVP_PKEY* privK, unsigned char* dig_sign);   // return dig sign length
        bool verifyDigSign(unsigned char* dig_sign, unsigned int dig_sign_len, EVP_PKEY* pub_key, unsigned char* msg_buf, unsigned int msg_len);

        //void generateNonce();
        int generateNonce(unsigned char *nonce);
        bool checkNonce(unsigned char *received_nonce, unsigned char *sent_nonce);

        bool generateECDHKey();    //generate ECDH key pair
        int deriveSecret();

        long serializePubKey(EVP_PKEY* key, unsigned char*& buf_key);
        int deserializePubKey(unsigned char* buf_key, unsigned int key_size, EVP_PKEY*& key); 
   
        bool checkCounter(uint32_t counter);
        //void sendMsg(const unsigned char* buffer, uint32_t msg_dim);
        //int receiveMsg(unsigned char *&rcv_buffer);

        uint32_t encryptMsg(unsigned char *plaintext, int pt_len, unsigned char *aad, unsigned char *output);  // encrypt message to send and return message length
        //unsigned int decryptMsg(unsigned char *ciphertext, int ct_len, int aad_len, unsigned char *plaintext, unsigned char *rcv_iv, unsigned char *tag);  // dencrypt received message and return message (pt) length
        uint32_t decryptMsg(unsigned char *input_buffer, int msg_size, unsigned char *aad, unsigned char *plaintext);  // dencrypt received message and return message (pt) length
        
        int fileList(unsigned char *plaintext, int pt_len, unsigned char* output_buf);    // return payload size
        //encrypt/decrypt()
        /* 
         * deriva shared secret
         * calcola chiave di sessione
         * 
         * incrementa contatore nella send e nella receive
        */
};
