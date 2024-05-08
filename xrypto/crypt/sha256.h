#pragma once
#define uint8  unsigned char
#define uint32 unsigned long int
#define uint64 unsigned __int64

#define SHA256_DIGEST_LENGTH 32

typedef struct {
    union {
        uint32 h[8];
        uint8 digest[32];
    };
    union {
        uint32 w[16];
        uint8 buffer[64];
    };
    size_t size;
    uint64 totalSize;
} sha256_context;

void sha256_starts(sha256_context* context);
void sha256_update(sha256_context* context, const void* data, size_t length);
void sha256_finish(sha256_context* context, uint8* digest);