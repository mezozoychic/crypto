#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

void print_hex_str(uint8_t *label, uint8_t *str, unsigned size);
uint8_t xtime(uint8_t x);
uint8_t Gmul_09(uint8_t x);
uint8_t Gmul_0B(uint8_t x);
uint8_t Gmul_0D(uint8_t x);
uint8_t Gmul_0E(uint8_t x);
void aes_key_expansion(const uint8_t *secret_key, uint8_t *sub_keys);
uint8_t *aes_encrypt(const uint8_t *secret_key, uint8_t *initialization_vector, 
                const uint8_t *plain_text);
uint8_t *aes_decrypt(const uint8_t *secret_key, const uint8_t *IV, unsigned cipher_len,
                uint8_t *cipher_text);

#define AES_128 1
#define AES_192 0
#define AES_256 0

#define AES_ECB  0
#define AES_CBC  1
// #define PCBC 0

#define AES_BLOCKSIZE 16

#if defined(AES_128) && (AES_128 == 1)
#define AES_KEYLEN   128
#define AES_ROUNDNUM 10
#elif defined(AES_192) && (AES_192 == 1)
#define AES_KEYLEN   192
#define AES_ROUNDNUM 12
#elif defined(AES_256) && (AES_256 == 1)
#define AES_KEYLEN   256
#define AES_ROUNDNUM 14
#endif

#define Nk (AES_KEYLEN / 32)

static const uint8_t s_box[16 * 16] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t r_s_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t r_con[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


void print_hex_str(uint8_t *label, uint8_t *str, unsigned size)
{
    printf("%s: ", label);
    for (int i = 0; i < size; ++i)
        printf("%02x", str[i]);

    printf("\n");
}


#define xtime(x)  ((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b)

// x * 9 = (((x * 2) * 2) * 2) ^ x;
#define Gmul_09(x)  xtime(xtime(xtime(x))) ^ x

// x * 11 = ((((x * 2) * 2) + x) * 2) + x;
#define Gmul_0B(x)  xtime(xtime(xtime(x)) ^ x) ^ x

// x * 13 = ((((x * 2) + x) * 2) * 2) + x
#define Gmul_0D(x)  xtime(xtime(xtime(x) ^ x)) ^ x

// x * 14 = ((((x * 2) + x) * 2) + x) * 2
#define Gmul_0E(x)  xtime(xtime(xtime(x) ^ x) ^ x)


void aes_key_expansion(const uint8_t *secret_key, uint8_t *sub_keys)
{
    unsigned i, j, k;
    uint8_t temp[4];

    for (i = 0; i < Nk; ++i)
    {
        *(sub_keys + i * 4 + 0) = *(secret_key + i * 4 + 0);
        *(sub_keys + i * 4 + 1) = *(secret_key + i * 4 + 1);
        *(sub_keys + i * 4 + 2) = *(secret_key + i * 4 + 2);
        *(sub_keys + i * 4 + 3) = *(secret_key + i * 4 + 3);
    }

    for (i = Nk; i < (4 * (AES_ROUNDNUM + 1)); ++i)
    {
        j = (i - 1) * 4;
        temp[0] = *(sub_keys + j + 0);
        temp[1] = *(sub_keys + j + 1);
        temp[2] = *(sub_keys + j + 2);
        temp[3] = *(sub_keys + j + 3);

        if (i % Nk == 0)
        {
            // RotWord()
            uint8_t b0 = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = b0;

            // SubWord()
            temp[0] = s_box[temp[0]];
            temp[1] = s_box[temp[1]];
            temp[2] = s_box[temp[2]];
            temp[3] = s_box[temp[3]];

            // + Round Constant
            temp[0] = temp[0] ^ r_con[i/Nk - 1];
        }

#if defined(AES_256) && (AES_256 == 1)
        if (i % Nk == 4)
        {
            temp[0] = s_box[temp[0]];
            temp[1] = s_box[temp[1]];
            temp[2] = s_box[temp[2]];
            temp[3] = s_box[temp[3]];
        }
#endif

        j = i * 4;
        k = (i - Nk) * 4;
        *(sub_keys + j + 0) = *(sub_keys + k + 0) ^ temp[0];
        *(sub_keys + j + 1) = *(sub_keys + k + 1) ^ temp[1];
        *(sub_keys + j + 2) = *(sub_keys + k + 2) ^ temp[2];
        *(sub_keys + j + 3) = *(sub_keys + k + 3) ^ temp[3];
    }

    // print_hex_str(sub_keys, 176);
}

uint8_t *aes_encrypt(const uint8_t *secret_key, uint8_t *initialization_vector, 
                 const uint8_t *text)
{
    uint8_t state[4][4], IV[4][4], a[4][4];
    unsigned nblocks, pad_size, i, j, k, r_k_i;
    uint8_t *sub_keys, *plain_text, *cipher_text;
    
    nblocks = (strlen((char *) text) / AES_BLOCKSIZE) + 1;
	cipher_text = (uint8_t *) malloc((nblocks * AES_BLOCKSIZE) * sizeof(uint8_t));

    // prepare plain text
    plain_text = (uint8_t *) malloc((nblocks * AES_BLOCKSIZE) * sizeof(uint8_t));
    for (i = 0; *text != '\0'; ++i)
        *(plain_text + i) = *text++;

    pad_size = nblocks * AES_BLOCKSIZE - i;

    // struct timeval time;
    // gettimeofday(&time, NULL);
    // double seed = (((time.tv_sec * 2654435789U) + time.tv_usec) * 2654435789U) + getpid();
    // srand(seed);

    for (; i < (nblocks * AES_BLOCKSIZE) - 1; ++i)
        *(plain_text + i) = rand() % 255;

    *(plain_text + i) = pad_size;

    // printf("plain text: \n");
    // print_hex_str(plain_text, nblocks * AES_BLOCKSIZE);

    //prepare IV
    for (i = 0; i < 4; ++i)
    {
		j = i * 4;

        IV[0][i] = *(initialization_vector + j + 0);
        IV[1][i] = *(initialization_vector + j + 1);
        IV[2][i] = *(initialization_vector + j + 2);
        IV[3][i] = *(initialization_vector + j + 3);
    }


    // expand key
    sub_keys = (uint8_t*) malloc((AES_ROUNDNUM + 1) * 4 * 4);
    aes_key_expansion(secret_key, sub_keys);


    // main loop
    memset(state[0], 0, AES_BLOCKSIZE);
    for (unsigned bi = 0; bi < nblocks; ++bi)
    {
        // CBC mode
        if (AES_CBC == 1)
        {
			j = bi * AES_BLOCKSIZE;
            for (i = 0; i < 4; ++i)
            {
                k = j + i * 4;

                state[0][i] = *(plain_text + k + 0) ^ IV[0][i];
                state[1][i] = *(plain_text + k + 1) ^ IV[1][i];
                state[2][i] = *(plain_text + k + 2) ^ IV[2][i];
                state[3][i] = *(plain_text + k + 3) ^ IV[3][i];
            }
        }

        // AddRoundKey()
        for (i = 0; i < 4; ++i)
        {
            j = i * 4;

            state[0][i] = state[0][i] ^ *(sub_keys + j + 0);
            state[1][i] = state[1][i] ^ *(sub_keys + j + 1);
            state[2][i] = state[2][i] ^ *(sub_keys + j + 2);
            state[3][i] = state[3][i] ^ *(sub_keys + j + 3);
        }

        for (unsigned r_i = 0; r_i < AES_ROUNDNUM; ++r_i)
        {
            // SBox() (substitution bytes)
            for (i = 0; i < 4; ++i)
            {
                state[0][i] = s_box[state[0][i]];
                state[1][i] = s_box[state[1][i]];
                state[2][i] = s_box[state[2][i]];
                state[3][i] = s_box[state[3][i]];
            }

            // ShiftRows() (circular shift left bytes)
            // 0 1 2 3      0 1 2 3
            // 0 1 2 3      1 2 3 0
            // 0 1 2 3  =>  2 3 0 1
            // 0 1 2 3      3 0 1 2
            uint8_t tmp1, tmp2;
            tmp1 = state[1][0];
            state[1][0] = state[1][1];
            state[1][1] = state[1][2];
            state[1][2] = state[1][3];
            state[1][3] = tmp1;

            tmp1 = state[2][0];
            tmp2 = state[2][1];
            state[2][0] = state[2][2];
            state[2][1] = state[2][3];
            state[2][2] = tmp1;
            state[2][3] = tmp2;

            tmp1 = state[3][3];
            state[3][3] = state[3][2];
            state[3][2] = state[3][1];
            state[3][1] = state[3][0];
            state[3][0] = tmp1;

            // MixColumns() (except last round)
            //
            //          r0     02 03 01 01     a0
            //          r1     01 02 03 01     a1
            //          r2  =  01 01 02 03  x  a2
            //          r3     03 01 01 02     a3
            //
            //          r0 = 2*a0 + 3*a1 + 1*a2 + 1*a3
            //          r1 = 1*a0 + 2*a1 + 3*a2 + 1*a3
            //          r2 = 1*a0 + 1*a1 + 2*a2 + 3*a3
            //          r3 = 3*a0 + 1*a1 + 1*a2 + 2*a3
            //
            // Multiplications are according to GF(2^8) arithmetic.
            // Additions are XOR operations.
            if (r_i != AES_ROUNDNUM - 1)
            {
                for (i = 0; i < 4; ++i)
                    for (j = 0; j < 4; ++j)
                        a[i][j] = state[i][j];


                for (i = 0; i < 4; ++i)
                {
                    state[0][i] = xtime(a[0][i]) ^ (xtime(a[1][i]) ^ a[1][i]) ^ a[2][i] ^ a[3][i];
                    state[1][i] = a[0][i] ^ xtime(a[1][i]) ^ (xtime(a[2][i]) ^ a[2][i]) ^ a[3][i];
                    state[2][i] = a[0][i] ^ a[1][i] ^ xtime(a[2][i]) ^ (xtime(a[3][i]) ^ a[3][i]);
                    state[3][i] = (xtime(a[0][i]) ^ a[0][i]) ^ a[1][i] ^ a[2][i] ^ xtime(a[3][i]);                                                  
                }
            }

            // AddRoundKey()
            r_k_i = ((r_i + 1) * 4) * 4;
            for (i = 0; i < 4; ++i)
            {
				j = i * 4;

                state[0][i] = state[0][i] ^ *(sub_keys + r_k_i + j + 0);
                state[1][i] = state[1][i] ^ *(sub_keys + r_k_i + j + 1);
                state[2][i] = state[2][i] ^ *(sub_keys + r_k_i + j + 2);
                state[3][i] = state[3][i] ^ *(sub_keys + r_k_i + j + 3);
            }
        }

		j = bi * AES_BLOCKSIZE;
        for (i = 0; i < 4; ++i)
        {
			k = j + i * 4;
            *(cipher_text + k + 0) = state[0][i];
            *(cipher_text + k + 1) = state[1][i];
            *(cipher_text + k + 2) = state[2][i];
            *(cipher_text + k + 3) = state[3][i];
        }

        //CBC mode
        if (AES_CBC == 1)
        {
            for (i = 0; i < 4; ++i)
            {
                j = i * 4;

                IV[0][i] = state[0][i];
                IV[1][i] = state[1][i];
                IV[2][i] = state[2][i];
                IV[3][i] = state[3][i];
            }
        }
    }

    free(plain_text);

	return cipher_text;
}


uint8_t *aes_decrypt(const uint8_t *secret_key, const uint8_t *IV, unsigned cipher_len,
                     uint8_t *cipher_text)
{
	unsigned nblocks = cipher_len / AES_BLOCKSIZE;
	uint8_t *plain_text = (uint8_t *) malloc((nblocks * AES_BLOCKSIZE + 1) * sizeof(uint8_t));
    uint8_t state[4][4];
    unsigned i, j, k, r_i, r_k_i, pad, pt_len;
	uint8_t temp1, temp2;
	uint8_t a[4][4];
    uint8_t *sub_keys = (uint8_t*) malloc((AES_ROUNDNUM + 1) * 4 * 4);

    aes_key_expansion(secret_key, sub_keys);

    
    for (unsigned bi = (nblocks-1); bi != -1; --bi)
    {
		j = bi * AES_BLOCKSIZE;
        for (i = 0; i < 4; ++i)
        {
            k = j + i * 4;

            state[0][i] = *(cipher_text + k + 0);
            state[1][i] = *(cipher_text + k + 1);
            state[2][i] = *(cipher_text + k + 2);
            state[3][i] = *(cipher_text + k + 3);
        }


        for (r_i = AES_ROUNDNUM; r_i > 0; --r_i)
        {
            // AddRoundKey()
            r_k_i = (r_i * 4) * 4;
            for (i = 0; i < 4; ++i)
            {
				j = r_k_i + i * 4;
                state[0][i] = state[0][i] ^ *(sub_keys + j + 0);
                state[1][i] = state[1][i] ^ *(sub_keys + j + 1);
                state[2][i] = state[2][i] ^ *(sub_keys + j + 2);
                state[3][i] = state[3][i] ^ *(sub_keys + j + 3);
            }

            // inverse MixColumns()
            //
            //  r0     0E 0B 0D 09     a0
            //  r1     09 0E 0B 0D     a1
            //  r2  =  0D 09 0E 0B  x  a2
            //  r3     0B 0D 09 0E     a3
            //
            //  r0 = 0E*a0 + 0B*a1 + 0D*a2 + 09*a3
            //  r1 = 09*a0 + 0E*a1 + 0B*a2 + 0D*a3
            //  r2 = 0D*a0 + 09*a1 + 0E*a2 + 0B*a3
            //  r3 = 0B*a0 + 0D*a1 + 09*a2 + 0E*a3
            //
            // Multiplications are according to GF(2^8) arithmetic.
            // Additions are XOR operations.
            if (r_i != AES_ROUNDNUM)
            {
                for (i = 0; i < 4; ++i)
                    for (j = 0; j < 4; ++j)
                        a[i][j] = state[i][j];

                for (i = 0; i < 4; ++i)
                {
                    state[0][i] = Gmul_0E(a[0][i]) ^ Gmul_0B(a[1][i]) ^ Gmul_0D(a[2][i]) ^ Gmul_09(a[3][i]);
                    state[1][i] = Gmul_09(a[0][i]) ^ Gmul_0E(a[1][i]) ^ Gmul_0B(a[2][i]) ^ Gmul_0D(a[3][i]);
                    state[2][i] = Gmul_0D(a[0][i]) ^ Gmul_09(a[1][i]) ^ Gmul_0E(a[2][i]) ^ Gmul_0B(a[3][i]);
                    state[3][i] = Gmul_0B(a[0][i]) ^ Gmul_0D(a[1][i]) ^ Gmul_09(a[2][i]) ^ Gmul_0E(a[3][i]);
                }
            }

            // inverse ShiftRows()
            temp1 = state[1][3];
            state[1][3] = state[1][2];
            state[1][2] = state[1][1];
            state[1][1] = state[1][0];
            state[1][0] = temp1;

            temp1 = state[2][3];
            temp2 = state[2][2];
            state[2][3] = state[2][1];
            state[2][2] = state[2][0];
            state[2][1] = temp1;
            state[2][0] = temp2;

            temp1 = state[3][0];
            state[3][0] = state[3][1];
            state[3][1] = state[3][2];
            state[3][2] = state[3][3];
            state[3][3] = temp1;

            // inverse SBox()
            for (i = 0; i < 4; ++i)
            {
                state[0][i] = r_s_box[state[0][i]];
                state[1][i] = r_s_box[state[1][i]];
                state[2][i] = r_s_box[state[2][i]];
                state[3][i] = r_s_box[state[3][i]];
            }
        }

        // AddRoundKey()
		j = bi * AES_BLOCKSIZE;
        for (i = 0; i < 4; ++i)
        {
            k = i * 4;

            plain_text[j + k + 0] = state[0][i] ^ sub_keys[k + 0];
            plain_text[j + k + 1] = state[1][i] ^ sub_keys[k + 1];
            plain_text[j + k + 2] = state[2][i] ^ sub_keys[k + 2];
            plain_text[j + k + 3] = state[3][i] ^ sub_keys[k + 3];
        }

        // CBC mode
        if (AES_CBC == 1)
        {
            if (bi > 0)
            {
                for (i = 0; i < 4; ++i)
                {
                    j = i * 4;

                    plain_text[bi * AES_BLOCKSIZE + j + 0] ^= cipher_text[((bi - 1) * AES_BLOCKSIZE) + j + 0];
                    plain_text[bi * AES_BLOCKSIZE + j + 1] ^= cipher_text[((bi - 1) * AES_BLOCKSIZE) + j + 1];
                    plain_text[bi * AES_BLOCKSIZE + j + 2] ^= cipher_text[((bi - 1) * AES_BLOCKSIZE) + j + 2];
                    plain_text[bi * AES_BLOCKSIZE + j + 3] ^= cipher_text[((bi - 1) * AES_BLOCKSIZE) + j + 3];
                }
            }
            else if (bi == 0)
            {
                for (i = 0; i < 4; ++i)
                {
                    j = i * 4;

                    plain_text[j + 0] ^= IV[j + 0];
                    plain_text[j + 1] ^= IV[j + 1];
                    plain_text[j + 2] ^= IV[j + 2];
                    plain_text[j + 3] ^= IV[j + 3];
                }
            }
        }
    }

    // Delete padding
    pad = plain_text[nblocks * AES_BLOCKSIZE - 1];
	pt_len = (nblocks-1) * AES_BLOCKSIZE + (AES_BLOCKSIZE - pad);
	plain_text[pt_len] = '\0';

	return plain_text;
}


int main()
{
    uint8_t *text = "secret text";
    uint8_t *IV = "1122334455667788";
    char *secret_key = "6bc1bee22e409f96";
    printf("text: %s\n", text);

    uint8_t *cipher_text = aes_encrypt(secret_key, IV, text);

    unsigned nblocks = (strlen(text) / AES_BLOCKSIZE) + 1;
	unsigned n = nblocks * AES_BLOCKSIZE;
	print_hex_str("cipher text", cipher_text, n);

	uint8_t *decrypted_text = aes_decrypt(secret_key, IV, n, cipher_text);
    printf("decrypted text: %s\n", decrypted_text);


    free(cipher_text);
	free(decrypted_text);
}


