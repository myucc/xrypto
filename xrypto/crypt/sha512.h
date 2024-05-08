#pragma once
#define uint8  unsigned char
#define uint32 unsigned long int
#define uint64 unsigned __int64

typedef struct {
    union {
        uint64 h[8];
        uint8 digest[64];
    };
    union {
        uint64 w[16];
        uint8 buffer[128];
    };
    size_t size;
    uint64 totalSize;
} sha512_context;

#define SHA512_DIGEST_LENGTH 64

void sha512_starts(sha512_context* context);
void sha512_update(sha512_context* context, const void* data, size_t length);
void sha512_finish(sha512_context* context, uint8* digest);