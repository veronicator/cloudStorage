
// Operation codes
#define LOGIN 0
#define UPLOAD_REQ 1
#define DOWNLOAD_REQ 2
#define RENAME_REQ 3
#define DELETE_REQ 4
#define FILE_LIST_REQ 5
#define UPLOAD 6
#define DOWNLOAD 7
#define DELETE 8
#define FILE_LIST 9
#define END_OP 10
#define LOGOUT 11
#define HELP 12
#define ERROR 13


//responses
#define MESSAGE_OK "ack_operation_req"
#define OP_TERMINATED "ack_operation_terminated"
#define MALFORMED_FILENAME "Filename not correct"
#define FILE_NOT_FOUND "File not found in the Cloud Storage"
#define FILE_FOUND "File already in the Cloud Storage. Delete or rename the file on the cloud before upload"
#define CLIENT_LOGOUT "Close this client session"

// whitelist
#define USERNAME_OK_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_@&!"
#define FILENAME_OK_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+-_.!@#$%^&()~"

//Response Msg
//#define MESSAGE_OK "ack_upload_req"
#define DOWNLOAD_TERMINATED "ack_download_term"
#define MESSAGE_INVALID_COMMAND "\n\tERROR: Invalid Entered Command\n"

// Server info
#define SRV_PORT 4242

// Variables size
#define MAX_COMMAND_SIZE 10
#define MAX_NAME_SIZE 20
#define MAX_CLIENTS 50
// to check/decide size
#define MAX_BUF_SIZE 20000
#define FRAGM_SIZE 8192  // 8 KiB - dimensione frammento del file da inviare
#define MAX_FILE_DIMENSION 4294967296

//
#define NUMERIC_FIELD_SIZE sizeof(uint32_t)   // size (in bytes) of fields containing dimension
#define OPCODE_SIZE sizeof(uint16_t)
#define FILE_SIZE_FIELD sizeof(uint64_t)
#define AAD_LEN (NUMERIC_FIELD_SIZE + OPCODE_SIZE)

#define NONCE_SIZE 4

#define HASH_FUN EVP_sha256()
#define DIGEST_SIZE EVP_MD_size(HASH_FUN)

#define CIPHER_AE EVP_aes_128_gcm()
#define BLOCK_SIZE EVP_CIPHER_block_size(CIPHER_AE)
#define IV_LEN EVP_CIPHER_iv_length(CIPHER_AE)
#define TAG_SIZE 16

#define MIN_LEN IV_LEN + NUMERIC_FIELD_SIZE + OPCODE_SIZE + TAG_SIZE