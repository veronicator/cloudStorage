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
#include <cerrno>
#include <cstring>
#include <signal.h> //for signal handler
#include "symbols.h"

using namespace std;
namespace fs = std::experimental::filesystem;

void handleErrors();

void handleErrors(const char *error);

void handleErrors(const char *error, int sockd);

/*
void generateRandomValue(unsigned char* new_value, int value_size) {
    if(RAND_poll() != 1) { cerr << "Error in RAND_poll\n"; exit(1); }
    if(RAND_bytes((unsigned char*)&new_value[0], value_size) != 1) { cerr << "Error in RAND_bytes\n"; exit(1); }
}
*/
//void readUsername(string& usr);

void readInput(string& input, const size_t MAX_SIZE, string);  // read MAX_SIZE charachters from standard input and put them in "input" string
void readFilenameInput(string& input, string msg);

char* canonicalizationPath(string file_dir_path);
long getFileSize(string canon_file_path);
int removeFile(string canon_path);


void print_progress_bar(int total, unsigned int fragment);

int  catch_the_signal(); // Register signal and signal handler
void custom_act(int signum); //the function to be called when signal is sent to process (handler)

void clear_vec(vector<unsigned char>& v);
//void clear_arr(unsigned char* arr, int arr_len);

class Session {
    unsigned char* session_key = nullptr;
    uint32_t send_counter = 0;
    uint32_t rcv_counter = 0;

    void incrementCounter(uint32_t& counter);
    int computeSessionKey(unsigned char* secret, int slen);  //shared secret -> session key

    int generateRandomValue(unsigned char* new_value, int value_size);
    
    public:
        EVP_PKEY* ECDH_myKey = nullptr;    // ephimeral 
        EVP_PKEY* ECDH_peerKey = nullptr;  // ephimeral

        Session() {};
        ~Session(); //deallocare tutti i vari buffer utilizzati: session_key ecc

        // Session utils
        uint32_t createAAD(unsigned char* aad, uint16_t opcode); // return aad_len
        // void readInput(string& input, const int MAX_SIZE, string msg = "");  // read MAX_SIZE charachters from standard input and put in "input" string


        EVP_PKEY* retrievePrivKey(string path);  // retrieve its own private key from pem file and return it
        int computeHash(unsigned char* msg, int len, unsigned char*& msgDigest);
        long signMsg(unsigned char* msg_to_sign, unsigned int msg_to_sign_len, EVP_PKEY* privK, unsigned char* dig_sign);   // return dig sign length
        bool verifyDigSign(unsigned char* dig_sign, unsigned int dig_sign_len, EVP_PKEY* pub_key, unsigned char* msg_buf, unsigned int msg_len);

        int generateNonce(unsigned char *nonce);
        bool checkNonce(unsigned char *received_nonce, unsigned char *sent_nonce);

        bool generateECDHKey();    //generate ECDH key pair
        int deriveSecret();

        long serializePubKey(EVP_PKEY* key, unsigned char*& buf_key);
        int deserializePubKey(unsigned char* buf_key, unsigned int key_size, EVP_PKEY*& key); 
   
        bool checkCounter(uint32_t counter);

        uint32_t encryptMsg(unsigned char *plaintext, size_t pt_len, unsigned char *aad, unsigned char *output);  // encrypt message to send and return message length
        uint32_t decryptMsg(unsigned char *input_buffer, uint64_t payload_size, unsigned char *aad, unsigned char *plaintext);  // dencrypt received message and return message (pt) length

        //encrypt/decrypt()
        /* 
         * deriva shared secret
         * calcola chiave di sessione
         * 
         * incrementa contatore nella send e nella receive
        */
};
