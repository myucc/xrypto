#include "aes128_xxx.h"

uint32 FSb[256], FT0[256], FT1[256], FT2[256], FT3[256];
uint32 RSb[256], RT0[256], RT1[256], RT2[256], RT3[256];
uint32 RCON[256],KT0[256], KT1[256], KT2[256], KT3[256];
int do_init = 1;
int KT_init = 1;

#define ROTR8(x)(((x<<24)&0xFFFFFFFF)|((x&0xFFFFFFFF)>>8))
#define XTIME(x)((x<<1)^((x&0x80)?0x1B:0x00))
#define MUL(x,y)((x&&y)?pow[(log[x]+log[y])%255]:0)

#define GET_UINT32(n,b,i)                       \
{                                               \
    (n) = ( (uint32) (b)[(i)    ] << 24 )       \
        | ( (uint32) (b)[(i) + 1] << 16 )       \
        | ( (uint32) (b)[(i) + 2] <<  8 )       \
        | ( (uint32) (b)[(i) + 3]       );      \
}

#define PUT_UINT32(n,b,i)                       \
{                                               \
    (b)[(i)    ] = (uint8) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8) ( (n)       );       \
}

void aes_gen_tables(void) {
    int i;
    uint8 x, y, pow[256], log[256];
    for (i = 0, x = 1; i < 256; i++, x ^= XTIME(x)) { pow[i] = x; log[x] = i; }
    for (i = 0, x = 1; i < 10; i++, x = XTIME(x)) RCON[i] = (uint32)x << 24;
    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;
    for (i = 1; i < 256; i++) {
        x = pow[255 - log[i]];
        y = x;  y = (y << 1) | (y >> 7);
        x ^= y; y = (y << 1) | (y >> 7);
        x ^= y; y = (y << 1) | (y >> 7);
        x ^= y; y = (y << 1) | (y >> 7);
        x ^= y ^ 0x63;
        FSb[i] = x;
        RSb[x] = i;
    }

    for (i = 0; i < 256; i++) {
        x = (unsigned char)FSb[i]; y = XTIME(x);
        FT0[i] = (uint32)(x ^ y) ^ ((uint32)x << 8) ^ ((uint32)x << 16) ^ ((uint32)y << 24);
        FT0[i] &= 0xFFFFFFFF;
        FT1[i] = ROTR8(FT0[i]);
        FT2[i] = ROTR8(FT1[i]);
        FT3[i] = ROTR8(FT2[i]);
        y = (unsigned char)RSb[i];
        RT0[i] = ((uint32)MUL(0x0B, y)) ^ ((uint32)MUL(0x0D, y) << 8) ^ ((uint32)MUL(0x09, y) << 16) ^ ((uint32)MUL(0x0E, y) << 24);
        RT0[i] &= 0xFFFFFFFF;
        RT1[i] = ROTR8(RT0[i]);
        RT2[i] = ROTR8(RT1[i]);
        RT3[i] = ROTR8(RT2[i]);
    }
}

int aes_set_key(aes_context* ctx, uint8* key, int nbits)
{
    int i;
    uint32* RK, * SK;
    if (do_init) { aes_gen_tables(); do_init = 0; }

    switch (nbits) {
    case 128: ctx->nr = 10; break;
    case 192: ctx->nr = 12; break;
    case 256: ctx->nr = 14; break;
    default: return(1);
    }

    RK = ctx->erk;
    for (i = 0; i < (nbits >> 5); i++) GET_UINT32(RK[i], key, i * 4);

    switch (nbits)
    {
    case 128:

        for (i = 0; i < 10; i++, RK += 4)
        {
            RK[4] = RK[0] ^ RCON[i] ^
                (FSb[(uint8)(RK[3] >> 16)] << 24) ^
                (FSb[(uint8)(RK[3] >> 8)] << 16) ^
                (FSb[(uint8)(RK[3])] << 8) ^
                (FSb[(uint8)(RK[3] >> 24)]);

            RK[5] = RK[1] ^ RK[4];
            RK[6] = RK[2] ^ RK[5];
            RK[7] = RK[3] ^ RK[6];
        }
        break;

    case 192:

        for (i = 0; i < 8; i++, RK += 6)
        {
            RK[6] = RK[0] ^ RCON[i] ^
                (FSb[(uint8)(RK[5] >> 16)] << 24) ^
                (FSb[(uint8)(RK[5] >> 8)] << 16) ^
                (FSb[(uint8)(RK[5])] << 8) ^
                (FSb[(uint8)(RK[5] >> 24)]);

            RK[7] = RK[1] ^ RK[6];
            RK[8] = RK[2] ^ RK[7];
            RK[9] = RK[3] ^ RK[8];
            RK[10] = RK[4] ^ RK[9];
            RK[11] = RK[5] ^ RK[10];
        }
        break;

    case 256:

        for (i = 0; i < 7; i++, RK += 8)
        {
            RK[8] = RK[0] ^ RCON[i] ^
                (FSb[(uint8)(RK[7] >> 16)] << 24) ^
                (FSb[(uint8)(RK[7] >> 8)] << 16) ^
                (FSb[(uint8)(RK[7])] << 8) ^
                (FSb[(uint8)(RK[7] >> 24)]);

            RK[9] = RK[1] ^ RK[8];
            RK[10] = RK[2] ^ RK[9];
            RK[11] = RK[3] ^ RK[10];

            RK[12] = RK[4] ^
                (FSb[(uint8)(RK[11] >> 24)] << 24) ^
                (FSb[(uint8)(RK[11] >> 16)] << 16) ^
                (FSb[(uint8)(RK[11] >> 8)] << 8) ^
                (FSb[(uint8)(RK[11])]);

            RK[13] = RK[5] ^ RK[12];
            RK[14] = RK[6] ^ RK[13];
            RK[15] = RK[7] ^ RK[14];
        }
        break;
    }

    if (KT_init)
    {
        for (i = 0; i < 256; i++)
        {
            KT0[i] = RT0[FSb[i]];
            KT1[i] = RT1[FSb[i]];
            KT2[i] = RT2[FSb[i]];
            KT3[i] = RT3[FSb[i]];
        }

        KT_init = 0;
    }

    SK = ctx->drk;

    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;

    for (i = 1; i < ctx->nr; i++)
    {
        RK -= 8;

        *SK++ = KT0[(uint8)(*RK >> 24)] ^
            KT1[(uint8)(*RK >> 16)] ^
            KT2[(uint8)(*RK >> 8)] ^
            KT3[(uint8)(*RK)]; RK++;

        *SK++ = KT0[(uint8)(*RK >> 24)] ^
            KT1[(uint8)(*RK >> 16)] ^
            KT2[(uint8)(*RK >> 8)] ^
            KT3[(uint8)(*RK)]; RK++;

        *SK++ = KT0[(uint8)(*RK >> 24)] ^
            KT1[(uint8)(*RK >> 16)] ^
            KT2[(uint8)(*RK >> 8)] ^
            KT3[(uint8)(*RK)]; RK++;

        *SK++ = KT0[(uint8)(*RK >> 24)] ^
            KT1[(uint8)(*RK >> 16)] ^
            KT2[(uint8)(*RK >> 8)] ^
            KT3[(uint8)(*RK)]; RK++;
    }

    RK -= 8;

    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;

    return(0);
}

void aes_encrypt(aes_context* ctx, uint8 input[16], uint8 output[16])
{
    uint32* RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->erk;
    GET_UINT32(X0, input, 0); X0 ^= RK[0];
    GET_UINT32(X1, input, 4); X1 ^= RK[1];
    GET_UINT32(X2, input, 8); X2 ^= RK[2];
    GET_UINT32(X3, input, 12); X3 ^= RK[3];

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    RK += 4;                                    \
                                                \
    X0 = RK[0] ^ FT0[ (uint8) ( Y0 >> 24 ) ] ^  \
                 FT1[ (uint8) ( Y1 >> 16 ) ] ^  \
                 FT2[ (uint8) ( Y2 >>  8 ) ] ^  \
                 FT3[ (uint8) ( Y3       ) ];   \
                                                \
    X1 = RK[1] ^ FT0[ (uint8) ( Y1 >> 24 ) ] ^  \
                 FT1[ (uint8) ( Y2 >> 16 ) ] ^  \
                 FT2[ (uint8) ( Y3 >>  8 ) ] ^  \
                 FT3[ (uint8) ( Y0       ) ];   \
                                                \
    X2 = RK[2] ^ FT0[ (uint8) ( Y2 >> 24 ) ] ^  \
                 FT1[ (uint8) ( Y3 >> 16 ) ] ^  \
                 FT2[ (uint8) ( Y0 >>  8 ) ] ^  \
                 FT3[ (uint8) ( Y1       ) ];   \
                                                \
    X3 = RK[3] ^ FT0[ (uint8) ( Y3 >> 24 ) ] ^  \
                 FT1[ (uint8) ( Y0 >> 16 ) ] ^  \
                 FT2[ (uint8) ( Y1 >>  8 ) ] ^  \
                 FT3[ (uint8) ( Y2       ) ];   \
}

    AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 1 */
    AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);       /* round 2 */
    AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 3 */
    AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);       /* round 4 */
    AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 5 */
    AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);       /* round 6 */
    AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 7 */
    AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);       /* round 8 */
    AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 9 */

    if (ctx->nr > 10)
    {
        AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);   /* round 10 */
        AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);   /* round 11 */
    }

    if (ctx->nr > 12)
    {
        AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);   /* round 12 */
        AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);   /* round 13 */
    }

    RK += 4;

    X0 = RK[0] ^ (FSb[(uint8)(Y0 >> 24)] << 24) ^
        (FSb[(uint8)(Y1 >> 16)] << 16) ^
        (FSb[(uint8)(Y2 >> 8)] << 8) ^
        (FSb[(uint8)(Y3)]);

    X1 = RK[1] ^ (FSb[(uint8)(Y1 >> 24)] << 24) ^
        (FSb[(uint8)(Y2 >> 16)] << 16) ^
        (FSb[(uint8)(Y3 >> 8)] << 8) ^
        (FSb[(uint8)(Y0)]);

    X2 = RK[2] ^ (FSb[(uint8)(Y2 >> 24)] << 24) ^
        (FSb[(uint8)(Y3 >> 16)] << 16) ^
        (FSb[(uint8)(Y0 >> 8)] << 8) ^
        (FSb[(uint8)(Y1)]);

    X3 = RK[3] ^ (FSb[(uint8)(Y3 >> 24)] << 24) ^
        (FSb[(uint8)(Y0 >> 16)] << 16) ^
        (FSb[(uint8)(Y1 >> 8)] << 8) ^
        (FSb[(uint8)(Y2)]);

    PUT_UINT32(X0, output, 0);
    PUT_UINT32(X1, output, 4);
    PUT_UINT32(X2, output, 8);
    PUT_UINT32(X3, output, 12);
}

void aes_decrypt(aes_context* ctx, uint8 input[16], uint8 output[16])
{
    uint32* RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->drk;

    GET_UINT32(X0, input, 0); X0 ^= RK[0];
    GET_UINT32(X1, input, 4); X1 ^= RK[1];
    GET_UINT32(X2, input, 8); X2 ^= RK[2];
    GET_UINT32(X3, input, 12); X3 ^= RK[3];

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    RK += 4;                                    \
                                                \
    X0 = RK[0] ^ RT0[ (uint8) ( Y0 >> 24 ) ] ^  \
                 RT1[ (uint8) ( Y3 >> 16 ) ] ^  \
                 RT2[ (uint8) ( Y2 >>  8 ) ] ^  \
                 RT3[ (uint8) ( Y1       ) ];   \
                                                \
    X1 = RK[1] ^ RT0[ (uint8) ( Y1 >> 24 ) ] ^  \
                 RT1[ (uint8) ( Y0 >> 16 ) ] ^  \
                 RT2[ (uint8) ( Y3 >>  8 ) ] ^  \
                 RT3[ (uint8) ( Y2       ) ];   \
                                                \
    X2 = RK[2] ^ RT0[ (uint8) ( Y2 >> 24 ) ] ^  \
                 RT1[ (uint8) ( Y1 >> 16 ) ] ^  \
                 RT2[ (uint8) ( Y0 >>  8 ) ] ^  \
                 RT3[ (uint8) ( Y3       ) ];   \
                                                \
    X3 = RK[3] ^ RT0[ (uint8) ( Y3 >> 24 ) ] ^  \
                 RT1[ (uint8) ( Y2 >> 16 ) ] ^  \
                 RT2[ (uint8) ( Y1 >>  8 ) ] ^  \
                 RT3[ (uint8) ( Y0       ) ];   \
}

    AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 1 */
    AES_RROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);       /* round 2 */
    AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 3 */
    AES_RROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);       /* round 4 */
    AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 5 */
    AES_RROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);       /* round 6 */
    AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 7 */
    AES_RROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);       /* round 8 */
    AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);       /* round 9 */

    if (ctx->nr > 10)
    {
        AES_RROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);   /* round 10 */
        AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);   /* round 11 */
    }

    if (ctx->nr > 12)
    {
        AES_RROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);   /* round 12 */
        AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);   /* round 13 */
    }

    RK += 4;

    X0 = RK[0] ^ (RSb[(uint8)(Y0 >> 24)] << 24) ^
        (RSb[(uint8)(Y3 >> 16)] << 16) ^
        (RSb[(uint8)(Y2 >> 8)] << 8) ^
        (RSb[(uint8)(Y1)]);

    X1 = RK[1] ^ (RSb[(uint8)(Y1 >> 24)] << 24) ^
        (RSb[(uint8)(Y0 >> 16)] << 16) ^
        (RSb[(uint8)(Y3 >> 8)] << 8) ^
        (RSb[(uint8)(Y2)]);

    X2 = RK[2] ^ (RSb[(uint8)(Y2 >> 24)] << 24) ^
        (RSb[(uint8)(Y1 >> 16)] << 16) ^
        (RSb[(uint8)(Y0 >> 8)] << 8) ^
        (RSb[(uint8)(Y3)]);

    X3 = RK[3] ^ (RSb[(uint8)(Y3 >> 24)] << 24) ^
        (RSb[(uint8)(Y2 >> 16)] << 16) ^
        (RSb[(uint8)(Y1 >> 8)] << 8) ^
        (RSb[(uint8)(Y0)]);

    PUT_UINT32(X0, output, 0);
    PUT_UINT32(X1, output, 4);
    PUT_UINT32(X2, output, 8);
    PUT_UINT32(X3, output, 12);
}