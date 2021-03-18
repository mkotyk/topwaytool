#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>

typedef enum result { OK = 0, ERROR, MEM_ERROR, IO_ERROR } result_t;

#define NELEM(x) (sizeof(x)/sizeof(x[0]))
#define MIN(a,b) ((a<b)?a:b)

const static int key_size = 16;
const static int hash_size = 16;
const uint8_t key_a[] = {0xC1, 0x81, 0x56, 0xC2, 0x44, 0xBD, 0x11, 0xE1, 0x94, 0x38, 0x00, 0x0C, 0x29, 0xBA, 0x27, 0xC0};
const uint8_t key_b[] = {0x81, 0x6B, 0xAE, 0x89, 0x3F, 0x95, 0xE6, 0xDB, 0x96, 0xA3, 0xB9, 0x90, 0x57, 0x17, 0x29, 0xAF};
#define key(index) (key_a[index] ^ key_b[index])

#define fprint_hex(f, pre, data) { \
    fprintf(f, "%s", pre); \
    for(int index =0; index < sizeof(data); index++) { \
        fprintf(f, "%02x", ((uint8_t*)data)[index]); \
    } \
    fprintf(f, "\n"); \
}

typedef result_t (*block_process_t)(uint8_t* data, size_t bytes_read, void* context);

result_t block_processor(FILE* in, size_t block_size, size_t bytes_to_be_processed, block_process_t process, void* context) {
    size_t bytes_processed = 0;
    size_t bytes_to_read;
    size_t bytes_read;
    uint8_t* buffer;
    result_t result = OK;

    if ((buffer = malloc(block_size)) == NULL) {
        return MEM_ERROR;
    }

    while(bytes_processed != bytes_to_be_processed) {
        bytes_to_read = MIN(block_size, bytes_to_be_processed - bytes_processed);
        if ((bytes_read = fread(buffer, 1, bytes_to_read, in)) != bytes_to_read) {
            result = IO_ERROR;
            break;
        }

        if (result = process(buffer, bytes_read, context) != OK) {
            break;
        }
        bytes_processed += bytes_read;
    }
    free(buffer);

    return result;
}

void obfuscate_block(uint8_t* key_block, uint8_t* data, uint8_t* digest) {
    MD5_CTX md5_context;
    uint8_t buffer[key_size * 3];
    int index;

    for(index = 0; index < key_size; index++) {
        buffer[index] = key_block[index];
        buffer[index + key_size] = data[index];
        buffer[index + key_size + key_size] = key(index);
    }

    MD5_Init(&md5_context);
    MD5_Update(&md5_context, buffer, sizeof(buffer));
    MD5_Final(buffer, &md5_context);

    for(index = 0; index < key_size; index++) {
        buffer[index + key_size] = key_b[index];
    }

    MD5_Init(&md5_context);
    MD5_Update(&md5_context, buffer, key_size * 2);
    MD5_Final(digest, &md5_context);
}

result_t md5_block_processor(uint8_t* data, size_t bytes_read, void* context) {
    return MD5_Update((MD5_CTX*) context, data, bytes_read) == 1?OK:ERROR;
}

result_t md5_hash_file(FILE* in, size_t length, uint8_t* digest) {
    result_t result = OK;
    MD5_CTX md5_context;
    MD5_Init(&md5_context);

    if ((result = block_processor(in, 4096, length, &md5_block_processor, &md5_context)) != OK) {
        return result;
    }

    MD5_Final(digest, &md5_context);
    return result;
}

typedef struct {
    uint8_t key_block[16];
    uint8_t xor_block[16];
    FILE* out;
} de_obfuscate_context_t;

result_t de_obfuscate_block_processor(uint8_t* data, size_t bytes_read, void* context) {
    de_obfuscate_context_t* ctx = (de_obfuscate_context_t*) context;
    int index;

    obfuscate_block(ctx->key_block, ctx->xor_block, ctx->xor_block);
    for(index = 0; index < hash_size; index++) {
        data[index] ^= ctx->xor_block[index];
    }
    if (fwrite(data, 1, bytes_read, ctx->out) != bytes_read) {
        fprintf(stderr, "Unable to write output block\n");
        return IO_ERROR;
    }
    return OK;
}

result_t decrypt_image(FILE* in, FILE* out) {
    size_t file_size;
    size_t content_size;
    uint8_t file_md5hash[hash_size];
    uint8_t computed_md5hash[hash_size];
    de_obfuscate_context_t context;
    context.out = out;

    fseek(in, 0L, SEEK_END);
    file_size = ftell(in);
    content_size = file_size - (hash_size + key_size);
    if (content_size < 0 || (content_size % 16) != 0) {
        fprintf(stderr, "Source file too small or not a multiple of %d.\n", hash_size);
        return ERROR;
    }
    fseek(in, content_size, SEEK_SET);

    if (fread(context.key_block, sizeof(uint8_t), key_size, in) != key_size) {
        fprintf(stderr, "Unable to read the key block.\n");
        return IO_ERROR;
    }

    if (fread(file_md5hash, sizeof(uint8_t), hash_size, in) != hash_size) {
        fprintf(stderr, "Unable to read the MD5 hash of the source file.\n");
        return IO_ERROR;
    }

    fseek(in, 0L, SEEK_SET);
    if (md5_hash_file(in, file_size - hash_size, computed_md5hash) != OK) {
        fprintf(stderr, "Error processing md5 hashing.\n");
        return ERROR;
    }

    obfuscate_block(context.key_block, computed_md5hash, computed_md5hash);

    fprint_hex(stderr, "Key                :", context.key_block);
    fprint_hex(stderr, "Read MD5 hash      :", file_md5hash);
    fprint_hex(stderr, "Calculated MD5 hash:", computed_md5hash);

    if (memcmp(file_md5hash, computed_md5hash, hash_size) != 0) {
        fprintf(stderr, "Hashes don't match. Stopping.\n");
        return ERROR;
    }

    fprintf(stderr, "Hashes match.  Continuing.\n");

    fprintf(stderr, "Working...\r");
    memset(context.xor_block, 0, sizeof(context.xor_block));
    fseek(in, 0L, SEEK_SET);
    return block_processor(in, hash_size, content_size, &de_obfuscate_block_processor, &context);
}

result_t encrypt_image(FILE* in, FILE* out) {
}

result_t chksum_block_processor(uint8_t* data, size_t bytes_read, void *context) {
    uint32_t* checksum = (uint32_t*) context;
    uint32_t* cast_data = (uint32_t*) data;
    int index;
    for(index = 0; index < bytes_read / sizeof(uint32_t); index++) {
        *checksum += cast_data[index];
    }
    return OK;
}

result_t chksum(FILE* in, size_t content_size, uint32_t* checksum) {
    const uint32_t block_size = 256;;
    result_t result;
    *checksum = 0xFFFFFFFF;
    if ((result = block_processor(in, block_size, content_size, &chksum_block_processor, checksum)) == OK) {
        *checksum = ~(*checksum);
    }
    return result;
}

result_t verify_checksum(FILE* in) {
    uint32_t read_checksum = 0;
    uint32_t computed_checksum = 0;
    int checksum_size = sizeof(uint32_t);

    size_t file_size;
    fseek(in, 0, SEEK_END);
    file_size = ftell(in);

    if (file_size == 0 ||
        file_size % checksum_size != 0 ||
        ((file_size - checksum_size) % 1024) != 0) {
        fprintf(stderr, "This file doesn't appear to have a %d byte checksum appended to it.\n", checksum_size);
        return ERROR;
    }

    fseek(in, file_size - checksum_size, SEEK_SET);
    if (fread(&read_checksum, checksum_size, 1, in) != 1) {
        fprintf(stderr, "Unable to read checksum from file.\n");
        return IO_ERROR;
    }

    fseek(in, 0, SEEK_SET);
    fprintf(stderr, "Working...\r");
    if (chksum(in, file_size - checksum_size, &computed_checksum) != OK) {
        fprintf(stderr, "Error computing checksum.\n");
        return ERROR;
    }

    fprintf(stderr, "Read checksum is    : %08X\n", read_checksum);
    fprintf(stderr, "Computed checksum is: %08X\n", computed_checksum);
    return read_checksum != computed_checksum;
}

result_t update_checksum(FILE* in) {
    size_t file_size;
    uint32_t computed_checksum = 0;
    int checksum_size = sizeof(uint32_t);
    uint8_t update = 1;

    fseek(in, 0, SEEK_END);
    file_size = ftell(in);
    update = (file_size % 1024) != 0 ;
    if (update) {
        file_size -= checksum_size;
    }
    fprintf(stderr, "File size indicates checksum needs to be %s.\n", update?"updated":"added");
    fseek(in, 0, SEEK_SET);
    fprintf(stderr, "Working...\r");
    if (chksum(in, file_size, &computed_checksum) != OK) {
        fprintf(stderr, "Error computing checksum.\n");
        return ERROR;
    }
    fprintf(stderr, "Computed checksum is: %08X\n", computed_checksum);
    if (fwrite(&computed_checksum, checksum_size, 1, in) != 1) {
        fprintf(stderr, "Error writing checksum.\n");
        return IO_ERROR;
    }

    return OK;
}

void help() {
    fprintf(stderr, "TopWay Tool Usage:\n\n");
    fprintf(stderr, "    -h     help (this message)\n");
    fprintf(stderr, "    -c     command.  Valid commands are verify, update, encrypt, decrypt\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "           verify - verify checksum in system.img file\n");
    fprintf(stderr, "           update - update checksum in system.img file\n");
    fprintf(stderr, "           encrypt - encrypt a boot.img or vendor.img file\n");
    fprintf(stderr, "           decrypt - decrypt a boot.img or vendor.img file\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    -s     source file or - for stdin\n");
    fprintf(stderr, "    -d     destination file or - for stdout\n");
}

int main(int argc, char*argv[]) {
    enum command_t { verify, update, encrypt, decrypt };
    int opt;
    int result = 0;
    char *src_file = NULL;
    char *dst_file = NULL;
    char *cmd = NULL;
    FILE *in, *out;
    enum command_t command;

    while((opt = getopt(argc, argv, "hc:s:d:")) >= 0) {
        switch(opt) {
            case 'h':
                help();
                return result;
            case 'c':
                cmd = optarg;
                break;
            case 's':
                src_file = optarg;
                break;
            case 'd':
                dst_file = optarg;
                break;
        }
    }

    if(cmd == NULL) {
        help();
        return result;
    } else if (strcmp(cmd, "verify") == 0) {
        command = verify;
    } else if (strcmp(cmd, "update") == 0) {
        command = update;
    } else if (strcmp(cmd, "decrypt") == 0) {
        command = decrypt;
    } else if (strcmp(cmd, "encrypt") == 0) {
        command = encrypt;
    } else {
        fprintf(stderr, "Unknown command [%s]\n", cmd);
        return 1;
    }


    while(1) {
        if (src_file == NULL) {
            fprintf(stderr, "No source file specified.\n");
            result = 1;
            break;
        }

        if (strcmp(src_file,"-") == 0) {
            in = stdin;
        } else {
            in = fopen(src_file, (command == update)?"r+b":"rb");
        }

        if (in == NULL) {
            fprintf(stderr, "Unable to open source file [%s]\n", src_file);
            result = 1;
            break;
        }

        if(command == verify || command == update) {
            /* Source only commands */
            switch(command) {
                case verify:
                    result = verify_checksum(in);
                    break;
                case update:
                    result = update_checksum(in);
                    break;
            }
            fclose(in);
        } else {
            /* Source and Destination commands */
            if (dst_file == NULL) {
                fprintf(stderr, "No destination file specified.\n");
                result = 1;
                fclose(in);
                break;
            }

            if (strcmp(dst_file,"-") == 0) {
                out = stdout;
            } else {
                out = fopen(dst_file, "wb");
            }

            if (out == NULL) {
                fprintf(stderr, "Unable to open destination file [%s]\n", dst_file);
                result = 1;
                fclose(in);
                break;
            }

            switch(command){
                case decrypt:
                    result = decrypt_image(in, out);
                    break;
                case encrypt:
                    result = encrypt_image(in, out);
                    break;
            }
            fclose(in);
            fclose(out);
        }
        break;
    }

    return result;
}
