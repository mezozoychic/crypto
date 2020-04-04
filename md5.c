#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>


void print_hex_str(uint8_t *str, unsigned size)
{
    for (int i = 0; i < size; ++i)
        printf("%02x", str[i]);

    printf("\n");
}

// number of operations in each round
#define md5_n_ops  16

// size of plain text block in bytes
// 512 / 8 = 64
#define md5_size_pt_block  64

// size of cipher_text block in bytes
#define md5_size_ct_block  16

// number of 32bit words in 512bit block
#define md5_n_words  16

// number of rounds
#define md5_n_rounds  4

// size of 32bit word in bytes
#define md5_w_size  4


// Table Constants
uint32_t md5_table_const[64];

// IV
uint32_t a = 0x67452301;
uint32_t b = 0xefcdab89;
uint32_t c = 0x98badcfe;
uint32_t d = 0x10325476;

// number of bits to shift
int shift1r[4] = { 7, 12, 17, 22 };
int shift2r[4] = { 5,  9, 14, 20 };
int shift3r[4] = { 4, 11, 16, 23 };
int shift4r[4] = { 6, 10, 15, 21 };

// little endian word
uint32_t get_le_word32(uint8_t *input)
{
    return input[0] | (input[1] << 8) | (input[2] << 16) | (input[3] << 24);
}

// circular shift left
uint32_t left_rotate(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}
// #define left_rotate(x, n) ((uint32_t) (x) << (n)) | ((x) >> (32 - (n)))


uint8_t *md5_encrypt(const uint8_t *text)
{
    unsigned n_blocks, i, j, n, S;
    uint64_t length, F, X, T, tmp;
    uint8_t *plain_text, *cipher_text, *pt_ptr, *ct_ptr;

    length = strlen((char *) text);
    n_blocks = (length / md5_size_pt_block + 1);
    plain_text = (uint8_t *) malloc((n_blocks * md5_size_pt_block) * sizeof(uint8_t));
	cipher_text = (uint8_t *) malloc((n_blocks * md5_size_ct_block) * sizeof(uint8_t));

    // copy text to the block
    for (i = 0, n = strlen((char *) text); i < n; ++i)
        plain_text[i] = text[i];

    // uppend 1 bit
    plain_text[i] = 0x80;

    // fill remaining zeroes
    // - 8 bytes left for size
    for (++i; i < (n_blocks * md5_size_pt_block - 8); ++i)
        plain_text[i] = 0;

    // add length in bits (little-endian)
    length = n * 8;
    plain_text[i] = (uint8_t) length;          ++i;
    plain_text[i] = (uint8_t) (length >> 8);   ++i;
    plain_text[i] = (uint8_t) (length >> 16);  ++i;
    plain_text[i] = (uint8_t) (length >> 24);  ++i;
    plain_text[i] = (uint8_t) (length >> 32);  ++i;
    plain_text[i] = (uint8_t) (length >> 40);  ++i;
    plain_text[i] = (uint8_t) (length >> 48);  ++i;
    plain_text[i] = (uint8_t) (length >> 56);

    // prepare IV
    uint32_t A = a;
    uint32_t B = b;
    uint32_t C = c;
    uint32_t D = d;

    // calculate table constants
    uint64_t two_pow_32 = pow(2, 32);
    for (i = 0, n = sizeof(md5_table_const) / sizeof(uint32_t); i < n; ++i)
    {
        //
        md5_table_const[i] = two_pow_32 * fabs(sin(i + 1));
    }

    // main loop
	pt_ptr = plain_text;
	ct_ptr = cipher_text;
    while (n_blocks)
    {
        for (i = 0, n = md5_n_ops * md5_n_rounds; i < n; ++i)
        {
            if (i < 16)
            {
                // 1 round
                // F(B,C,D) = (B AND C) OR ((NOT B) AND D)
                F = (B & C) | ((~B) & D);
                // S - number of bits to shift
                S = shift1r[i % 4];
                // j - index of plain text word
                j = i;
            }
            else if ((i > 15) && (i < 32))
            {
                // 2 round
                // F(B,C,D) = (B AND D) OR (C AND (NOT D))
                F = (B & D) | (C & (~D));
                // S - number of bits to shift
                S = shift2r[i % 4];
                // j - index of plain text word
                j = (5 * i + 1) % 16;
            }
            else if ((i > 31) && (i < 48))
            {
                // 3 round
                // F(B,C,D) = B XOR C XOR D
                F = B ^ C ^ D;
                // S - number of bits to shift
                S = shift3r[i % 4];
                // j - index of plain text word
                j = (3 * i + 5) % 16;
            }
            else
            {
                // 3 round
                // F(B,C,D) = C XOR (B OR (NOT D))
                F = C ^ (B  | (~D));
                // S - number of bits to shift
                S = shift4r[i % 4];
                // j - index of plain text word
                j = (7 * i) % 16;
            }

            X = get_le_word32(plain_text + (j * md5_w_size));
            T = md5_table_const[i];

            tmp = B + left_rotate((A + F + X + T), S);
            A = D;
            D = C;
            C = B;
            B = tmp;
        }
        
        A += a;
        B += b;
        C += c;
        D += d;

        // copy result in cipher text block
        *(cipher_text + 0)  = (uint8_t) A;
        *(cipher_text + 1)  = (uint8_t) (A >> 8);
        *(cipher_text + 2)  = (uint8_t) (A >> 16);
        *(cipher_text + 3)  = (uint8_t) (A >> 24);
        *(cipher_text + 4)  = (uint8_t) B;
        *(cipher_text + 5)  = (uint8_t) (B >> 8);
        *(cipher_text + 6)  = (uint8_t) (B >> 16);
        *(cipher_text + 7)  = (uint8_t) (B >> 24);
        *(cipher_text + 8)  = (uint8_t) C;
        *(cipher_text + 9)  = (uint8_t) (C >> 8);
        *(cipher_text + 10) = (uint8_t) (C >> 16);
        *(cipher_text + 11) = (uint8_t) (C >> 24);
        *(cipher_text + 12) = (uint8_t) D;
        *(cipher_text + 13) = (uint8_t) (D >> 8);
        *(cipher_text + 14) = (uint8_t) (D >> 16);
        *(cipher_text + 15) = (uint8_t) (D >> 24);

        --n_blocks;
        plain_text += md5_size_pt_block;
        cipher_text += md5_size_ct_block;
    }

    free(pt_ptr);
	return ct_ptr;
}


int main()
{
    uint8_t *text = "password";

    uint8_t *cipher_text = md5_encrypt(text);

    unsigned lenght = strlen(text);
    unsigned n = (lenght / md5_size_pt_block + 1) * md5_size_ct_block;
    print_hex_str(cipher_text, n);

    free(cipher_text);
}