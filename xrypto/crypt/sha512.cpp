#include "sha512.h"

#define W(n) w[(n) & 0x0F]
#define CH(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR64(x, n) ((x) >> (n))
#define SIGMA1(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define SIGMA2(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define SIGMA3(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ SHR64(x, 7))
#define SIGMA4(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ SHR64(x, 6))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define SWAPINT64(x) ( \
    (((uint64)(x) & 0x00000000000000FFULL) << 56) | \
    (((uint64)(x) & 0x000000000000FF00ULL) << 40) | \
    (((uint64)(x) & 0x0000000000FF0000ULL) << 24) | \
    (((uint64)(x) & 0x00000000FF000000ULL) << 8) | \
    (((uint64)(x) & 0x000000FF00000000ULL) >> 8) | \
    (((uint64)(x) & 0x0000FF0000000000ULL) >> 24) | \
    (((uint64)(x) & 0x00FF000000000000ULL) >> 40) | \
    (((uint64)(x) & 0xFF00000000000000ULL) >> 56))

#define htobe64(value) SWAPINT64((uint64) (value))

static const uint8 padding[128] = {
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint64 k[80] = {
   0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
   0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
   0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
   0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
   0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
   0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
   0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
   0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
   0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
   0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
   0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
   0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
   0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
   0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
   0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
   0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
   0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
   0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
   0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
   0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
};

static void* zmemcpy(void* destination, const void* source, size_t size) {
    unsigned char* dest = static_cast<unsigned char*>(destination);
    const unsigned char* src = static_cast<const unsigned char*>(source);
    if (dest < src || dest >= (src + size)) for (size_t i = 0; i < size; ++i) dest[i] = src[i];
    else for (size_t i = size; i > 0; --i)dest[i - 1] = src[i - 1];
    return destination;
}

void sha512_process(sha512_context* context)
{
    unsigned int i;
    uint64 temp1, temp2;

    uint64 a = context->h[0];
    uint64 b = context->h[1];
    uint64 c = context->h[2];
    uint64 d = context->h[3];
    uint64 e = context->h[4];
    uint64 f = context->h[5];
    uint64 g = context->h[6];
    uint64 h = context->h[7];
    uint64* w = context->w;

    for (i = 0; i < 16; i++) w[i] = htobe64(w[i]);
    for (i = 0; i < 80; i++) {
        if (i >= 16) W(i) += SIGMA4(W(i + 14)) + W(i + 9) + SIGMA3(W(i + 1));
        temp1 = h + SIGMA2(e) + CH(e, f, g) + k[i] + W(i);
        temp2 = SIGMA1(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    context->h[0] += a;
    context->h[1] += b;
    context->h[2] += c;
    context->h[3] += d;
    context->h[4] += e;
    context->h[5] += f;
    context->h[6] += g;
    context->h[7] += h;
}

void sha512_starts(sha512_context* context)
{
    context->size = 0;
    context->totalSize = 0;
    context->h[0] = 0x6A09E667F3BCC908;
    context->h[1] = 0xBB67AE8584CAA73B;
    context->h[2] = 0x3C6EF372FE94F82B;
    context->h[3] = 0xA54FF53A5F1D36F1;
    context->h[4] = 0x510E527FADE682D1;
    context->h[5] = 0x9B05688C2B3E6C1F;
    context->h[6] = 0x1F83D9ABFB41BD6B;
    context->h[7] = 0x5BE0CD19137E2179;
}

void sha512_update(sha512_context* context, const void* data, size_t length)
{
    size_t n;
    while (length > 0)
    {
        n = MIN(length, 128 - context->size);
        zmemcpy(context->buffer + context->size, data, n);
        context->size += n;
        context->totalSize += n;
        data = (uint8*)data + n;
        length -= n;
        if (context->size == 128) {
            sha512_process(context);
            context->size = 0;
        }
    }
}

void sha512_finish(sha512_context* context, uint8* digest)
{
    unsigned int i;
    size_t paddingSize;
    uint64 totalSize;

    totalSize = context->totalSize * 8;
    if (context->size < 112)  paddingSize = 112 - context->size;
    else paddingSize = 128 + 112 - context->size;

    sha512_update(context, padding, paddingSize);
    context->w[14] = 0;
    context->w[15] = htobe64(totalSize);

    sha512_process(context);
    for (i = 0; i < 8; i++) context->h[i] = htobe64(context->h[i]);
    if (digest != 0) zmemcpy(digest, context->digest, 64);
}