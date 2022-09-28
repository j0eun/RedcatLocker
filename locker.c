#include "locker.h"

FILE* logger = 0;

int main(int argc, char** argv, char** envp)
{
    logger = stdout;
    int key_size = 0;
    char mode[MAX_MODE_LENGTH] = {0, };
    char target[MAX_PATH_LENGTH] = {0, };

    if (!parse_options(&key_size, mode, target, argc, argv))
    {
        print_usage();
        return EXIT_FAILURE;
    }
    fprintf(logger, "[+] bits: %d\n", key_size);
    fprintf(logger, "[+] mode: %s\n", mode);
    fprintf(logger, "[+] target: %s\n", target);

    if (!is_valid_options(&key_size, mode, target))
    {
        fprintf(logger, "[-] some option has invalid value!\n");
        return EXIT_FAILURE;
    }
    cvector_vector_type(char*) paths = 0;
    walkdir(&paths, target);
    for (int i = 0; i < cvector_size(paths); i++)
    {
        fprintf(logger, "path[%d]: %s\n", i, paths[i]);
    }

    for (int i = 0; i < cvector_size(paths); i++)
    {
        memset(paths[i], 0, MAX_PATH_LENGTH);
        free(paths[i]);
    }
    cvector_free(paths);
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
                memcpy(target, optarg, MAX_PATH_LENGTH-1);
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
            memcpy(target, optarg, MAX_PATH_LENGTH-1);
            break;
        default:
            return 0;
        }
    }
    return 1;
}

int is_valid_options(int* key_size, char* mode, char* target)
{
    DIR* dir = 0;

    switch (*key_size)
    {
    case 128:
    case 192:
    case 256:
        break;
    default:
        return 0;
    }
    for (int i = 0; i < MAX_MODE_LENGTH; i++)
    {
        mode[i] = tolower(mode[i]);
    }
    if (strncmp(mode, "aes-ecb", 7) && strncmp(mode, "aes-cbc", 7))
    {
        return 0;
    }
    dir = opendir(target);
    if (dir) {
        closedir(dir);
    } else if (ENOENT == errno) {
        return 0; // Directory does not exist.
    } else {
        return 0; // opendir() failed for some other reason.
    }
    return 1;
}

void walkdir(cvector_vector_type(char*)* paths, char* parent_dir)
{
    char* path = 0;
    struct dirent* ent;
    struct stat ent_info;
    DIR* dir = opendir(parent_dir);
    while (dir != 0)
    {
        ent = readdir(dir);
        if (ent == 0) 
            break;
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) 
            continue;
        path = (char*)calloc(1, MAX_PATH_LENGTH);
        snprintf(path, MAX_PATH_LENGTH-1, "%s/%s", parent_dir, ent->d_name);
        if (stat(path, &ent_info) == -1) 
        {
            continue;
        }
        if (S_ISDIR(ent_info.st_mode))
        {
            walkdir(paths, path);
            memset(path, 0, MAX_PATH_LENGTH);
            free(path);
        }
        else if (S_ISREG(ent_info.st_mode))
        {
            cvector_push_back(*paths, path);
        }
    }
    closedir(dir);
}