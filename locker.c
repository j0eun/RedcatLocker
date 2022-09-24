#include "locker.h"

FILE* logger = 0;

int main(int argc, char** argv, char** envp)
{
    logger = stdout;

    int opt = 0;
    int opt_idx = 0;
    char serial[16] = {0, };
    char target[256] = {0, };
    struct option options[] = {
        {"quiet", no_argument, 0, 0},
        {"serial", required_argument, 0, 0},
        {"target", required_argument, 0, 0},
        {0, 0, 0, 0},
    };
    while ((opt = getopt_long(argc, argv, "q:s:t:", options, &opt_idx)) != -1)
    {
        switch (opt_idx)
        {
            if (opt != 0) break;
            case 1:
                memcpy(serial, optarg, 16);
                break;
            case 2:
                memcpy(target, optarg, 256);
                break;
        }
        switch (opt)
        {
            case 'q':
                logger = fopen("/dev/0", "w");
                break;
            case 's':
                fprintf(logger, "serial: %s\n", serial);
                break;
            case 't':
                fprintf(logger, "target: %s\n", target);
                break;
            default:
                print_usage();
                return 1;
        }
    }
    if (is_valid_serial(serial) == 0)
    {
        fprintf(logger, "please input a valid serial code\n");
        return 1;
    }
    if (logger->_fileno != stdout->_fileno)
    {
        fclose(logger);
    }
    return 0;
}

void print_usage()
{
    char* man = "" \
        "Usage: \n" \
        "    ./locker [options] \n" \
        "\n" \
        "Options: \n" \
        "    -q, --quiet        blahblah \n" \
        "    -s, --serial       blahblah \n" \
        "    -t, --target       blahblah \n";
    fprintf(stdout, "%s\n", man);
}

int is_valid_serial(char* serial)
{
    return 0;
}