#include "security_utils.h"

/*
void handleErrors() {   
    perror("An error occurred\n"); 
    exit(1);
}
*/

void handleErrors(const char *error) {
    string msg_err = "An error occurred: ";
    msg_err.append(error);
    msg_err.append("\n");
    perror(msg_err.c_str());
    exit(EXIT_FAILURE);
}

/*
// manage the error and close the socket used with the client that has the error //
void handleErrors(const char *error, int sockd) {
    perror(error);
    close(sockd);
    pthread_exit(NULL);
}
*/


/********************************************************************/

/**
 * @return true if overflow, false otherwise
*/
bool checkSumOverflow(long a, long b) {
    return (b >= 0 && a > LONG_MAX - b) ||
        (b < 0 && a < LONG_MIN - b);
}

bool checkSumOverflow(uint32_t a, uint32_t b) {
    return a > UINT32_MAX - b;
}


/********************************************************************/

void clear_vec(vector<unsigned char> &v) {
    if (!v.empty()) {
        v.assign(v.size(), '0');
        v.clear();
    }
}

/** this method performs the canonicalization of a file name, 
 * to check if there is a directory traversal for that file
 * @file_dir_path: path of the directory containing the file to check
 */
char* canonicalizationPath(string file_dir_path) {

    char *canon_dir = realpath(file_dir_path.c_str(), NULL);
    if (!canon_dir) {
        cerr << "realpath returned NULL" << endl;
        free(canon_dir);
        return nullptr;
    }

    return canon_dir;
        
}

/** this method retrieve the file size of a file in the cloud storage of the user
 * @canon_file_path: path of the file requested
 * @return: the size of the file if found, -1 or -2 on error
*/
long getFileSize(string canon_file_path) {

    struct stat buffer;
    if (stat(canon_file_path.c_str(), &buffer) != 0) {
        cout << "File not found!" << endl;
        return -1;
    }
    
    if (buffer.st_size >= MAX_FILE_DIMENSION) {
        cerr << "File too big" << endl;
        return -2;
    }
    return buffer.st_size; 
}

void readFilenameInput(string& input, string msg) {

    bool string_ok = false;

    do
    {
        cout << msg << endl;
        getline(cin, input);

        if (!cin)
        { cerr << "\n === Error during input ===\n"; exit(EXIT_FAILURE); }

        if (input.empty()) continue;

        const auto re = regex{R"(^\w[\w\.\-\+_!#$%^&()]{0,19}$)"};
        string_ok = regex_match(input, re);

        if (!string_ok)
        { cout << "! FILE NAME HAS A WRONG FORMAT !" << endl; }
    
    } while (!string_ok);
}


void readInput(string& input, const size_t MAX_SIZE, string msg = "") {
    string ok_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_@&!";
    bool ok = false;
    do {
        if (!msg.empty())
            cout << msg << endl;
        getline(cin, input);
        if (!cin) {
            cerr << "Error during input\n";
            exit(EXIT_FAILURE);
        }
        if (input.length() == 0 || input.length() > MAX_SIZE || input.find_first_not_of(ok_chars) != string::npos) {
            cout << "Error: insert number of characters between 1 and " << MAX_SIZE << " without spaces\n";
            cout << "Allowed characters: " << ok_chars << endl;
            ok = false; 
        } else {
            ok = true;
        }
        
    } while (!ok);  // (input.length() == 0 || input.length() > MAX_SIZE || input.find_first_not_of(ok_chars) != string::npos);
}


/********************************************************************/

void Session::incrementCounter(uint32_t& counter) {
    counter = (counter + 1) % UINT32_MAX;
}

unsigned int Session::createAAD(unsigned char* aad, uint16_t opcode) {
    //cout << "session->createAAD" << endl;
    int aad_len = 0;
    //cout << sizeof(uint16_t) << " sizeof " << endl;
    uint32_t send_counter_n = htonl(send_counter);
    //cout << "send counter: " << send_counter << "\tcounter_n: " << send_counter_n << endl; 
    memcpy(aad, &send_counter_n, NUMERIC_FIELD_SIZE);
    aad_len += NUMERIC_FIELD_SIZE;
    incrementCounter(send_counter);
    // //BIO_dump_fp(stdout, (const char*)aad, aad_len); 
    // cout << "session->createAAD2 " << sizeof(*aad) << endl;
    
    uint16_t opcode_n = htons(opcode);
    memcpy(aad + aad_len, &opcode_n, OPCODE_SIZE);
    aad_len += OPCODE_SIZE;
    //cout << "session->createAAD3" << endl;
    ////BIO_dump_fp(stdout, (const char*)aad, aad_len); 
    return aad_len;
}

int Session::computeSessionKey(unsigned char* secret, int slen) {
    cout << "Session->computeSessionKey" << endl;
    // session key obtained from hashing shared secret
    return computeHash(secret, slen, session_key);
}

/********************************************************************/

/**
 * @return: 1 on success, -1 on failure
*/
int Session::generateRandomValue(unsigned char* new_value, int value_size) {
    //cout << "Session->generateRandomValue" << endl;
    if (new_value == NULL) {
        perror("generate random null pointer error ");
        return -1;
    }
    //cout << "random" << endl;
    if (RAND_poll() != 1) {
        cerr << "Error in RAND_poll\n";
        return -1;
    }
    if (RAND_bytes((unsigned char*)&new_value[0], value_size) != 1) {
        cerr << "Error in RAND_bytes\n";
        return -1;
    }
    //cout << "Session->generateRandomValue end" << endl;
    return 1;
}

EVP_PKEY* Session::retrievePrivKey(string path) {

    FILE *fileKey = fopen(path.c_str(), "r");
    if (!fileKey) {
        cerr << "Error: the file doesn't exist.\n";
        return nullptr;
    }
    EVP_PKEY* key = PEM_read_PrivateKey(fileKey, NULL, NULL, NULL);
    fclose(fileKey);
    if (!key) {
        cerr << "Error: PEM_read_PrivateKey returned NULL.\n";
        return nullptr;
    }
    return key;
}

/**
 * compute the hash of a message
 * @msg: message to hash
 * @msg_len: length in byte of the message to hash
 * @msg_digest: result of the hashing
 * @return: 1 on success, -1 on error
*/
int Session::computeHash(unsigned char* msg, int msg_len, unsigned char*& msg_digest) {
    cout << "computeHash" << endl;
    unsigned int dig_len;    // digest length

    // create & init context
    EVP_MD_CTX* hCtx;
    hCtx = EVP_MD_CTX_new();
    if (!hCtx) {
        perror("EVP_MD_CTX_new returned NULL");
        return -1;
    }
    // allocate mem for digest
    msg_digest = (unsigned char*)malloc(DIGEST_SIZE);
    if (!msg_digest) {
        perror("Malloc error msg_digest");
        return -1;
    }
    //hashing: init, update, finalize digest
    if (EVP_DigestInit(hCtx, HASH_FUN) != 1) {
        free(msg_digest);
        perror("DigestInit error");
        return -1;
    }
    if (EVP_DigestUpdate(hCtx, msg, msg_len) != 1) {
        free(msg_digest);
        perror("DigestUpdate error");
        return -1;
    }
    if (EVP_DigestFinal(hCtx, msg_digest, &dig_len) != 1) {
        free(msg_digest);
        perror("DigestFinal error");
        return -1;
    }
    //TODO: check for clean up
    
    // context deallocation
    EVP_MD_CTX_free(hCtx);
    return 1;
}

long Session::signMsg(unsigned char* msg_to_sign, unsigned int msg_to_sign_len, EVP_PKEY* privK, unsigned char* dig_sign) {
    cout << "session->signMsg" << endl;
    // create the signature context
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) { 
        cerr << "Error: EVP_MD_CTX_new returned NULL\n"; 
        return -1;
    }

    // sign the pt
    // perform a single update on the whole pt, assuming that the pt is not huge
    if (EVP_SignInit(md_ctx, HASH_FUN) != 1) {
        perror("SignInit error");
        return -1;
    }

    if (EVP_SignUpdate(md_ctx, msg_to_sign, msg_to_sign_len) != 1) {
        perror("SignUpdate error");
        return -1;
    }

    unsigned int sgnt_size;
    if (EVP_SignFinal(md_ctx, dig_sign, &sgnt_size, privK) != 1) {
        perror("SignFinal error");
        return -1;
    }
    
    // delete the digest from memory
    EVP_MD_CTX_free(md_ctx);
    //cout << "signMsg done" << endl;
    return sgnt_size;
}

bool Session::verifyDigSign(unsigned char* dig_sign, unsigned int dig_sign_len, EVP_PKEY* pub_key, unsigned char* msg_buf, unsigned int msg_len) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        perror("EVP_MD_CTX_new returned NULL");
        return false;
    }
    int ret;

    // verify the pt
    // performe a single update on the whole pt, assuming that the pt is not huge
    if (EVP_VerifyInit(md_ctx, HASH_FUN) != 1) {
        cerr << "EVP_VerifyInit error" << endl;
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    if (EVP_VerifyUpdate(md_ctx, msg_buf, msg_len) != 1) {
        cerr << "EVP_VerifyUpdate error" << endl;
        EVP_MD_CTX_free(md_ctx);
        return false;    
    }
    ret = EVP_VerifyFinal(md_ctx, dig_sign, dig_sign_len, pub_key);

    if (ret == -1) {
        cerr << "EVP_VerifyFinal error" << endl;
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    EVP_MD_CTX_free(md_ctx);    // deallocate data
    cout << "verifydigsign ret " << ret << endl;
    return ret == 1;
}

/********************************************************************/

int Session::generateNonce(unsigned char *nonce) {
    return generateRandomValue(nonce, NONCE_SIZE);    
}

bool Session::checkNonce(unsigned char* received_nonce, unsigned char *sent_nonce) {
    cout << "checkNonce -> received" << endl;
    ////BIO_dump_fp(stdout, (const char*)received_nonce, NONCE_SIZE);
    cout << "checkNonce -> sent" << endl;
    ////BIO_dump_fp(stdout, (const char*)sent_nonce, NONCE_SIZE);
    return memcmp(received_nonce, sent_nonce, NONCE_SIZE) == 0;
}

bool Session::generateECDHKey() {
    cout << "session->generateECDHkey" << endl;
    // create context for ECDH parameters
    EVP_PKEY* DH_params = NULL;
    EVP_PKEY_CTX* param_ctx;
    
    if (!(param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {   // puts the parameters for EC in the context
        cerr << "EVP_PKEY_CTX_new_id failed" << endl;
        // TODO: liberare risorse
        return false;
    }
    if (EVP_PKEY_paramgen_init(param_ctx) != 1) {
        cerr << "EVP_PKEY_paramgen_init failed" << endl;
        // TODO: liberare risorse
        return false;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, NID_X9_62_prime256v1) != 1) {
        cerr << "EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed" << endl;
        // TODO: liberare risorse
        return false;
    }
    if (EVP_PKEY_paramgen(param_ctx, &DH_params) != 1) {
        cerr << "EVP_PKEY_paramgen failed" << endl;
        // TODO: liberare risorse
        return false;
    }
    EVP_PKEY_CTX_free(param_ctx);

    // create context for key generation and generate a new ephimeral key
    EVP_PKEY_CTX* DH_ctx;
    
    if (!(DH_ctx = EVP_PKEY_CTX_new(DH_params, NULL))) {  // key generation
        cerr << "EVP_PKEY_CTX_new failed" << endl;
        // TODO: liberare risorse
        return false;
    }

    //EVP_PKEY* my_ECDHkey = NULL;
    if (EVP_PKEY_keygen_init(DH_ctx) != 1) {
        cerr << "ECP_PKEY_keygen_init failed" << endl;
        // TODO: liberare risorse
        return false;
    }
    if (EVP_PKEY_keygen(DH_ctx, &ECDH_myKey) != 1) {
        cerr << "EVP_PKEY_keygen failed" << endl;
        // TODO: liberare risorse
        return false;
    }
    EVP_PKEY_CTX_free(DH_ctx);    
    cout << "session->generateECDHKey done" << endl;
    return true;
}

// derive secrete & compute session key
int Session::deriveSecret() {
    cout << "session->deriveSecret" << endl;
    // shared secret derivation: create context and buffer 
    EVP_PKEY_CTX* derive_ctx;
    unsigned char* shared_secret = nullptr;
    size_t secret_len;

    if (!(derive_ctx = EVP_PKEY_CTX_new(ECDH_myKey, NULL))) {  // secret derivation
        perror("EVP_PKEY_CTX_new error");
        return -1;
    }

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        perror("EVP_PKEY_derive_init err");
        return -1;
    }
    if (EVP_PKEY_derive_set_peer(derive_ctx, ECDH_peerKey) <= 0) {
        perror("EVP_PKEY_derive_set_peer err");
        return -1;
    }

    // determine buffer length
    if (EVP_PKEY_derive(derive_ctx, NULL, &secret_len) <= 0) {
        perror("EVP_PKEY_derive err");
        return -1;
    }

    // derive shared secret
    shared_secret = (unsigned char*)malloc(secret_len);
    if (!shared_secret) {
        perror("Malloc error shared_secret");
        return -1;
    }
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &secret_len) <= 0) {
        perror("EVP_PKEY_derive error");
        return -1;
    }
    /* shared secret is secret_len bytes written to buffer shared_secret */

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(ECDH_peerKey);
    EVP_PKEY_free(ECDH_myKey);
    
    cout << "call to computeSessionkey" << endl;
    computeSessionKey(shared_secret, secret_len);

    free(shared_secret);
    // free(nonce);
    //nonce.fill('0');
    return 1;
}

/********************************************************************/

long Session::serializePubKey(EVP_PKEY* key, unsigned char*& buf_key) {
    cout << "session->serializePubKey" << endl;
    unsigned char* buf = nullptr;
    BIO* mBio = BIO_new(BIO_s_mem());
    if (!mBio) {
        cerr << "Error: BIO_new returned null\n";
        return -1;
    }
    if (PEM_write_bio_PUBKEY(mBio, key) != 1) {
        cerr << "Error: PEM_write_bio_PUBKEY failed\n";
        return -1;
    }
    uint32_t key_size = BIO_get_mem_data(mBio, &buf);
    buf_key = (unsigned char*)malloc(key_size);
    if (!buf_key) {
        perror("Malloc error buf_key");
        return -1;
    }
    memcpy(buf_key, buf, key_size);

    BIO_free(mBio);

    if (key_size < 0) {
        cerr << "Error: BIO_get_mem_data failed\n"; 
        return -1;
    }
    return key_size;
}

int Session::deserializePubKey(unsigned char* buf_key, unsigned int key_size, EVP_PKEY*& key) {
    BIO* mBio = BIO_new(BIO_s_mem());
    if (!mBio) {
        cerr << "Error: BIO_new returned null\n";
        return -1;
    }
    if (BIO_write(mBio, buf_key, key_size) <= 0) {
        cerr << "Error: BIO_write failed\n";
        return -1;
    }
    key = PEM_read_bio_PUBKEY(mBio, NULL, NULL, NULL);
    BIO_free(mBio);
    
    if (!key) {
        cerr << "Error: PEM_read_bio_PUBKEY returned NULL\n";
        return -1;
    }
    return 1;
}

bool Session::checkCounter(uint32_t counter) {
    //cout << "counter: " << rcv_counter << endl
    //    << "recv_counter: " << counter << endl;
    return counter == rcv_counter;
}

/********************************************************************/

uint32_t Session::encryptMsg(unsigned char *plaintext, size_t pt_len, unsigned char *aad, unsigned char *output) {
    //cout << "session->encryptMsg pt_len " << pt_len << endl;
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ct_len = 0;

    cout << "ENC_PLAIN" << endl;                
    //BIO_dump_fp(stdout, (const char*)plaintext, pt_len); 
    cout << "ENC_PT_LEN: " << pt_len << endl;

    unsigned char *ciphertext = (unsigned char*)malloc(pt_len + BLOCK_SIZE);
    if (!ciphertext) {
        perror("Malloc error CT");
        return 0;
    }
    unsigned char *tag = (unsigned char*)malloc(TAG_SIZE);
    if (!tag) {
        perror("Malloc error TAG");
        return 0;
    }

    //generate IV
    unsigned char* iv = (unsigned char*)malloc(IV_LEN);
    if (!iv) {
        perror("Malloc error IV");
        return 0;
    }
    memset(iv, 0, IV_LEN);
    generateRandomValue(iv, IV_LEN); 
    // cout << "session->encryptMsg2" << endl;

    // create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(iv);
        free(ciphertext);
        free(tag);
        perror("EVP_CIPHER_CTX_new failed");
        return 0;
    }
    // initialise the encryption operation
    if (EVP_EncryptInit(ctx, CIPHER_AE, session_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        perror("EVP_EncryptInit failed");
        return 0;
    }
    
    // provide any AAD data. this can be called zero or more time as required
    // //BIO_dump_fp(stdout, (const char*)aad, aad_len); 
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, AAD_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        perror("EVP_EncryptUpdate AAD failed");
        return 0;
    }
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        perror("EVP_EncryptUpdate CT failed");
        return 0;
    }
    ct_len = len;
    // finalise encryption
    if (EVP_EncryptFinal(ctx, ciphertext + ct_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        perror("EVP_EncryptFinal failed");
        return 0;
    }
    ct_len += len;
    // get the tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(iv);
        free(ciphertext);
        free(tag);
        perror("EVP_CIPHER_CTX_ctrl failed");
        return 0;
    }
    // clean up
    EVP_CIPHER_CTX_free(ctx);

    // cout << "session->encryptMsg3" << endl;

    if (MAX_BUF_SIZE - IV_LEN - AAD_LEN - ct_len - TAG_SIZE < NUMERIC_FIELD_SIZE) {
        cerr << "Error: msg too long" << endl;
        free(iv);
        free(ciphertext);
        free(tag);
        return 0;
    }

    uint32_t written_bytes = 0;
    memcpy(output, iv, IV_LEN);
    written_bytes += IV_LEN;
    memcpy(output + written_bytes, aad, AAD_LEN);
    written_bytes += AAD_LEN;
    // cout << "session->encryptMsg4" << endl;
    memcpy(output + written_bytes, ciphertext, ct_len);
    written_bytes += ct_len;
    // cout << "session->encryptMsg5" << endl;
    memcpy(output + written_bytes, tag, TAG_SIZE);
    written_bytes += TAG_SIZE;
    
    cout << "ENC_CT" << endl;
    //BIO_dump_fp(stdout, (const char*)ciphertext, ct_len); 

    free(iv);
    free(ciphertext);
    free(tag);
    //cout << "session-> encryptMsg end" << endl;
    return written_bytes;
}


uint32_t Session::decryptMsg(unsigned char *input_buffer, uint64_t payload_size, unsigned char *aad, unsigned char *plaintext) {
    //cout << "session->decryptMsg" << endl;
    EVP_CIPHER_CTX *ctx;
    int ct_len;
    int len = 0;    // numero di byte decifrati ad ogni giro
    uint32_t pt_len = 0;
    int ret;

    unsigned char *ciphertext = nullptr;   
    unsigned char *rcv_iv = (unsigned char*)malloc(IV_LEN);
    if (!rcv_iv) {
        perror("Malloc error rcv_iv");
        return 0;
    }
    unsigned char *tag = (unsigned char*)malloc(TAG_SIZE);
    if (!tag) {
        perror("Malloc error tag");
        return 0;
    }

 
    // read fields in buffer
    uint32_t read_bytes = NUMERIC_FIELD_SIZE;
    memcpy(rcv_iv, input_buffer + read_bytes, IV_LEN);
    read_bytes += IV_LEN;

    mempcpy(aad, input_buffer + read_bytes, AAD_LEN);
    read_bytes += AAD_LEN;
    
    //cout << "session->decrypt" << endl;
    ////BIO_dump_fp(stdout, (const char*)aad, AAD_LEN); 

    uint32_t counter = *(uint32_t*)(aad);
    //cout << "recev counter_n decry: " << counter << endl;
    counter = ntohl(counter);
    //cout << "recv counter h: " << counter << endl;
    if (!checkCounter(counter)) {
        free(rcv_iv);
        free(tag);
        perror("received counter not valid");
        return 0;
    }
    incrementCounter(rcv_counter);   

    ct_len = payload_size - AAD_LEN - IV_LEN - TAG_SIZE;
    if (ct_len <= 0) {
        free(rcv_iv);
        free(tag);
        cerr << "negative ct length not valid" << endl;
        return 0;
    }
    ciphertext = (unsigned char*)malloc(ct_len);
    if (!ciphertext) {
        free(rcv_iv);
        free(tag);
        perror("Malloc error ct");
        return 0;
    }
    mempcpy(ciphertext, input_buffer + read_bytes, ct_len);
    read_bytes += ct_len;

    cout << "DEC_CT" << endl;
    //BIO_dump_fp(stdout, (const char*)ciphertext, ct_len);

    mempcpy(tag, input_buffer + read_bytes, TAG_SIZE);
    read_bytes += TAG_SIZE;

    if (read_bytes - NUMERIC_FIELD_SIZE != payload_size) {
        free(rcv_iv);
        free(tag);
        free(ciphertext);
        cerr << "read_bytes error" << endl;
        return 0;
    }

    // create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(rcv_iv);
        free(tag);
        free(ciphertext);
        perror("EVP_CIPHER_CTX_new failed");
        return 0;
    }

    if (EVP_DecryptInit(ctx, CIPHER_AE, session_key, rcv_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(rcv_iv);
        free(tag);
        free(ciphertext);
        perror("EVP_DecryptInit failed");
        return 0;
    }
    
    // provide any AAD data
    if (EVP_DecryptUpdate(ctx, NULL, &len, aad, AAD_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(rcv_iv);
        free(tag);
        free(ciphertext);
        perror("EVP_DecryptUpdate failed");
        return 0;
    }
    // provide the msg to be decrypted and obtain the pt output
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(rcv_iv);
        free(tag);
        free(ciphertext);
        perror("EVP_DecryptUpdate failed");
        return 0;
    }
    pt_len += len;
    
    // set expected tag value
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(rcv_iv);
        free(tag);
        free(ciphertext);
        perror("EVP_CIPHER_CTX_ctrl failed");
        return 0;
    }
    
    /* finalise the decryption: a positive return value indicates success 
    * anything else is a failure -> the pt is not trustworthy */
   ret = EVP_DecryptFinal(ctx, plaintext + pt_len, &len);

   // clean up
   EVP_CIPHER_CTX_free(ctx);
   //EVP_CIPHER_CTX_cleanup(ctx);
    free(rcv_iv);
    free(tag);
    free(ciphertext);

    cout << "DEC_PLAIN" << endl;
    //BIO_dump_fp(stdout, (const char*)plaintext, pt_len);

    //cout << "RET: " << ret << endl;

   if (ret >= 0) {
       // success
       pt_len += len;
       //cout << "PT_LEN: " << pt_len << endl;
       return pt_len;
   } else {
       // verify failed
       return 0;
   }
}

int removeFile(string canon_path)
{
    /*char curr_dir[1024];
    string path;
    if(server_side)
        path = string(getcwd(curr_dir, sizeof(curr_dir))) + FILE_PATH_SERVER + username + "/" + filename;
    else
        path = string(getcwd(curr_dir, sizeof(curr_dir))) + FILE_PATH_CLIENT + username + "/" + filename;
    */
    if (remove(canon_path.c_str()) != 0) {   
        perror ("\n * * * ERROR");
        return -1;
    }
    return 1;
}

void print_progress_bar(int total, unsigned int fragment)
{
    cout << "\r" << "[Fragment " << fragment + 1 << " of " << total << "]";
	cout.flush();
    
    /*
        - Possibile alternativa -
        void
        progress_bar(int fragment)
        {        
            //while (fragment < 1)
            //{
                int barWidth = 70;

                cout << "[";
        
                int pos = barWidth * fragment;
                for (size_t i = 0; i < barWidth; ++i)
                {
                    if (i < pos)
                        cout << "=";
                    else if (i == pos)
                        cout << ">";
                    else
                        cout << " ";
                }
        
            cout << "] " << int(fragment+1) << " %\r";
            cout.flush();

            fragment += 0.16; // for demonstration only
        //}
        }
    */
}

/** Register signal and signal handler */
int catch_the_signal()
{
    int interrupt_signal, stop_signal;
    struct sigaction sig_int_handler;

    sig_int_handler.sa_handler = custom_act; //What to do

    sigemptyset(&sig_int_handler.sa_mask);  //initiailization of the signal set
                                            //pointed to by sigset_t var.
                                            //mask of signals which should be blocked
    sig_int_handler.sa_flags = 0;

    interrupt_signal = sigaction(SIGINT, &sig_int_handler, NULL);   //CTRL+C
    stop_signal =  sigaction(SIGTSTP, &sig_int_handler, NULL);      //CTRL+Z

    if (interrupt_signal == -1 || stop_signal == -1) { //sigaction() fails
        return -1;   
    } else {
        return 1;   
    }


    /*_Note:

        sigaction() returns 0 on success; on error, -1 is returned,
        and errno is set to indicate the error.

        - sigaction() insted of signal() system call because the latter is
        less portable when establishing a signal handler.
        In fact signal() behavior varies across UNIX versions, and has also varied
        historically across different versions of Linux -

        - prototype: int sigaction(int signum, const struct sigaction *restrict act,
                     struct sigaction *restrict oldact);

        - What to do once the signal is captured:
        1) default behavior (SIG_DFL, SIG_IGN)
        2) specific behaviors defined in a particular handler function
            based on our needs (my_handler function: custom_act in this case)


        - [ When we will use it ]

            if (catch_the_signal() == 0)
            {
                cout << "ERROR in signal handler phase: " << strerror(errno) << endl; return 0;  }
    */
}

/** the function to be called when signal is sent to process */
void custom_act(int signum)
{
    string choice;

    cout << "\n\t=== Caught signal with code: " << signum << " ===" << endl;

    //ToDo in a better suitable way
    //do_stuff: terminate program (e.g.)

    cout << "\n\t(The operation on cloud terminated) " << endl;

    cout << "\nThe File was not successfully Uploaded/Downloaded. \n" << endl;

    cout << "Do you want to go back to the Main Menu??: [y/n]\n" << endl;
    cout << "(y)-> Main Menu\n(n)-> Exit from Application" << endl;
    cout << "\n_Ans: ";
    getline(cin, choice);

    if (!cin)
    { cerr << "\n === Error during input ===\n" << endl; return; }

    while (choice != "Y" && choice!= "y" && choice != "N" && choice!= "n" )
    {
        cout << "\nError: The parameter of cohice is wrong!" << endl;
        cout << "(y)-> Main Menu\n(n)-> Exit from Application" << endl;
        cout << "\n-- Try again: [y/n]: ";
        getline(cin, choice);

        if (!cin)
        { cerr << "\n === Error during input ===\n" << endl; return; }
    }

    if (choice == "N" || choice == "n")
    {
        cout << "\n\t=== Exit from the Application ===\n" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "\n\t=== Welcome back in the main Menu ===\n" << endl;
    return;
}

/********************************************************************/


Session::~Session() {
    cout << "~Session" << endl;
    //TODO: check if everything is deallocated

    if (session_key != nullptr)
        free(session_key);
    /*
    cout << "session_key free" << endl;
    
    if (ECDH_myKey != nullptr)
        EVP_PKEY_free(ECDH_myKey);
    cout << "ecdh_mykey free " << endl;
    if (ECDH_peerKey != nullptr)
        EVP_PKEY_free(ECDH_peerKey);
    cout << "ecdh_peerk free" << endl;
    */
        
    //nonce.fill('0');
    //free(nonce);
    //free(iv);
    cout << "~Session end" << endl;
}
