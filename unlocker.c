#include "unlocker.h"

FILE* logger = 0;
pthread_mutex_t mutex;
int next_path_idx = 0;

int main(int argc, char** argv, char** envp)
{
    logger = stdout;
    char target[MAX_PATH_LENGTH] = {0, };

    if (!parse_options(target, argc, argv))
    {
        print_usage();
        return EXIT_FAILURE;
    }
    if (!is_valid_options(target))
    {
        fprintf(logger, "[-] some option has invalid value!\n");
        return EXIT_FAILURE;
    }
    fprintf(logger, "[+] recursive file searching under the target directory...\n");
    cvector_vector_type(char*) paths = 0;
    walkdir(&paths, target);
    fprintf(logger, "[+] %d infected files were found!\n", (int)cvector_size(paths));

    int hits = 0;
    fprintf(logger, "[+] starting file decryption process...\n");
    hits = do_decrypt(&paths);
    fprintf(logger, "[+] finished!\n");
    fprintf(logger, "[+] summary of statistics\n");
    fprintf(logger, "\t total: %d\n", (int)cvector_size(paths));
    fprintf(logger, "\t decrypted: %d\n", hits);

    return EXIT_SUCCESS;
}

void print_usage()
{
    char* man = "" \
        "Usage: \n" \
        "    ./unlocker [options] \n" \
        "\n" \
        "Options: \n" \
        "    -t, --target       required, target root directory path to decrypt (length is must be 256 under)\n" \
        "    -q, --quiet        optional, disable to logging \n";
    fprintf(stderr, "%s\n", man);
}

int parse_options(char* target, int argc, char** argv)
{
    int opt = 0;
    int opt_idx = 0;
    struct option options[] = {
        {"quiet", no_argument, 0, 'q'},
        {"target", required_argument, 0, 't'},
        {0, 0, 0, 0},
    };
    while ((opt = getopt_long(argc, argv, "t:q", options, &opt_idx)) != -1)
    {
        switch (opt)
        {
        case 0:
            switch (opt_idx)
            {
            case 1:
                memcpy(target, optarg, MAX_PATH_LENGTH-1);
                break;
            }
        case 'q':
            logger = fopen("/dev/null", "w");
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

int is_valid_options(char* target)
{
    DIR* dir = 0;

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
    DIR* dir = 0;
    char* path = 0;
    struct dirent* ent = 0;
    struct stat ent_info = {0, };
    
    dir = opendir(parent_dir);
    while (dir != 0)
    {
        ent = readdir(dir);
        if (ent == 0) 
            break;
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) 
            continue;
        path = (char*)calloc(MAX_PATH_LENGTH, 1);
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
        else if (S_ISREG(ent_info.st_mode) && !S_ISLNK(ent_info.st_mode))
        {
            if (!is_infected_file(path))
            {
                memset(path, 0, MAX_PATH_LENGTH);
                free(path);
                continue;
            }
            cvector_push_back(*paths, path);
        }
    }
    closedir(dir);
}

int is_infected_file(char* path)
{
    char* ptr = 0;
    
    ptr = strstr(path, INFECTED_FILE_EXT);
    if (ptr != 0)
    {
        return !strcmp(ptr, INFECTED_FILE_EXT);
    }
    return 0;
}

int do_decrypt(cvector_vector_type(char*)* paths)
{
    int hits = 0;
    int total = 0;
    int max_cores = 0;
    thread_args* args = 0;
    pthread_t* workers = 0;

    max_cores = sysconf(_SC_NPROCESSORS_ONLN); // get maximum number of CPU cores
    args = (thread_args*)calloc(1, sizeof(thread_args));
    workers = (pthread_t*)calloc(max_cores, sizeof(pthread_t));

    pthread_mutex_init(&mutex, 0);
    for (int i = 0; i < max_cores; i++)
    {
        args->paths = *paths;
        pthread_create(&workers[i], 0, (void*)worker_decryption_proc, args);
    } 
    for (int i = 0; i < max_cores; i++)
    {
        pthread_join(workers[i], (void*)&hits);
        total += hits;
    }
    pthread_mutex_destroy(&mutex);
    memset(workers, 0, max_cores*sizeof(pthread_t));
    memset(args, 0, sizeof(thread_args));
    free(args);
    free(workers);

    return total;
}

int worker_decryption_proc(thread_args* args)
{
    int hits = 0;
    int cur_path_idx = 0;
    while (1)
    {
        pthread_mutex_lock(&mutex);
        cur_path_idx = next_path_idx;
        if (cur_path_idx >= (int)cvector_size(args->paths))
        {
            pthread_mutex_unlock(&mutex);
            return hits;
        }
        next_path_idx++;
        pthread_mutex_unlock(&mutex);
        if (decrypt_file(args->paths[cur_path_idx]))
        {
            hits++;
        }
    }
}

int decrypt_file(char* original_path)
{
    int is_decrypted = 0;
//     int inl = 0;
//     int outl = 0;
//     FILE* infp = 0;
//     FILE* outfp = 0;
//     int file_sig = 0;
//     char* ciphername = 0;
//     int ciphername_id = 0;
//     unsigned char* in = 0;
//     unsigned char* out = 0;
//     char* renamed_path = 0;
//     unsigned char* iv = 0;
//     unsigned char* key = 0;
//     EVP_CIPHER_CTX* ctx = 0;
//     const EVP_CIPHER* cipher = 0;
    
//     in = (unsigned char*)calloc(BUFSIZ, 1);
//     out = (unsigned char*)calloc(BUFSIZ+EVP_MAX_BLOCK_LENGTH, 1);
//     renamed_path = (char*)calloc(MAX_PATH_LENGTH, 1);
//     ciphername = (char*)calloc(CIPHER_NAME_LENGTH, 1);

//     infp = fopen(original_path, "rb");
//     strncpy(renamed_path, original_path, strlen(original_path)-strlen(INFECTED_FILE_EXT));
//     outfp = fopen(renamed_path, "wb");
//     if (!infp && !outfp)
//     {
//         goto CLEANUP_AES_DECRYPTION;
//     }
//     // fseek(infp, -4, SEEK_END);
//     // fread(&file_sig, 4, 1, infp);
//     // if (file_sig != INFECTED_FILE_SIG)
//     // {
//     //     goto CLEANUP_AES_DECRYPTION;
//     // }
//     // fseek(infp, -8, SEEK_END);
//     // fread(&ciphername_id, 4, 1, infp);
//     // number_to_ciphername(ciphername, ciphername_id);
    
//     while ((outl = fread(in, 1, sizeof(in), infp)) > 0)
//     {
//         if (!EVP_DecryptUpdate(ctx, out, &outl, in, inl))
//         {
//             goto CLEANUP_AES_DECRYPTION;
//         }
//         fwrite(out, 1, outl, outfp);
//     }
//     EVP_CipherFinal_ex(ctx, out, &outl);
//     fwrite(out, 1, outl, outfp);

//     ctx = EVP_CIPHER_CTX_new();
//     EVP_CIPHER_CTX_init(ctx);
//     OpenSSL_add_all_ciphers();
//     cipher = EVP_get_cipherbyname(ciphername);
//     iv = (unsigned char*)calloc(EVP_CIPHER_iv_length(cipher), 1);
//     key = (unsigned char*)calloc(EVP_CIPHER_key_length(cipher), 1);

//     if (!gen_random_bytes(iv, EVP_CIPHER_iv_length(cipher)))
//     {
//         goto CLEANUP_GEN_RAND_BYTES;
//     }
//     if (!gen_random_bytes(key, EVP_CIPHER_key_length(cipher)))
//     {
//         goto CLEANUP_GEN_RAND_BYTES;
//     }
//     EVP_DecryptInit_ex(ctx, cipher, 0, key, iv);
    


//     // TODO: Implement RSA decryption for hiding AES key and IV
//     footer aes_metadata = {
//         iv,
//         key,
//         ciphername_to_number(ciphername),   // identifier for cipher block mode
//         INFECTED_FILE_SIG,                  // signature
//     };
//     fwrite(aes_metadata.iv, 1, EVP_CIPHER_iv_length(cipher), outfp);
//     fwrite(aes_metadata.key, 1, EVP_CIPHER_key_length(cipher), outfp);
//     fwrite(&aes_metadata.mode, 4, 1, outfp);
//     fwrite(&aes_metadata.signature, 4, 1, outfp);
//     is_decrypted = 1;
//     fprintf(logger, "\t decrypted: %s\n", renamed_path);
//     if (!remove(original_path))
//     {
//         fprintf(logger, "\t deleted: %s\n", original_path);
//     }

// CLEANUP_RSA_DECRYPTION:
//     aes_metadata = (footer){0, };
// CLEANUP_AES_DECRYPTION:
//     fclose(outfp);
//     fclose(infp);
//     memset(renamed_path, 0, MAX_PATH_LENGTH);
//     memset(out, 0, BUFSIZ+EVP_MAX_BLOCK_LENGTH);
//     memset(in, 0, BUFSIZ);
//     free(renamed_path);
//     free(out);
//     free(in);
// CLEANUP_GEN_RAND_BYTES:
//     memset(key, 0, EVP_CIPHER_key_length(cipher));
//     memset(iv, 0, EVP_CIPHER_iv_length(cipher));
//     free(key);
//     free(iv);
//     EVP_CIPHER_CTX_cleanup(ctx);

    return is_decrypted;
}

char* number_to_ciphername(char* ciphername, int mode)
{
    switch (mode)
    {
    case AES_128_ECB:
        strncpy(ciphername, "aes-128-ecb\x00", CIPHER_NAME_LENGTH);
        break;
    case AES_192_ECB:
        strncpy(ciphername, "aes-192-ecb\x00", CIPHER_NAME_LENGTH);
        break;
    case AES_256_ECB:
        strncpy(ciphername, "aes-256-ecb\x00", CIPHER_NAME_LENGTH);
        break;
    case AES_128_CBC:
        strncpy(ciphername, "aes-128-cbc\x00", CIPHER_NAME_LENGTH);
        break;
    case AES_192_CBC:
        strncpy(ciphername, "aes-192-cbc\x00", CIPHER_NAME_LENGTH);
        break;
    case AES_256_CBC:
        strncpy(ciphername, "aes-256-cbc\x00", CIPHER_NAME_LENGTH);
        break;
    }
    return ciphername;
}