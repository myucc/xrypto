#pragma once
#include "sha256.h"

#define uint8  unsigned char
#define uint32 unsigned long int

#define PROG_NAME "Encrypted"
#define PROG_VERSION "BLOWFISH128Z"

typedef struct{
    uint32 erk[64];
    uint32 drk[64];
    int nr;
} aes_context;

typedef struct {
    char aes[3];
    unsigned char version;
    unsigned char last_block_size;
} aescrypt_hdr;

typedef unsigned char sha256_t[32];

int aes_set_key(aes_context* ctx, uint8* key, int nbits);
void aes_encrypt(aes_context* ctx, uint8 input[16], uint8 output[16]);
void aes_decrypt(aes_context* ctx, uint8 input[16], uint8 output[16]);