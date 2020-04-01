#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

uint8_t B64_index_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                              'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                              'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                              'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

                    
uint8_t B64_padding = '=';

uint8_t *B64_encode(uint8_t *input, unsigned n)
{
    uint32_t int24word;
    unsigned len = 0;
	uint8_t *output = malloc(1024);

	uint8_t *out_ptr = output;
    for (unsigned i = 0; i < n; ++i)
    {
        int24word = input[i] << 0x10;
		++i;
		int24word |= (i < n) ? (input[i] << 0x08) : 0;
		++i;
		int24word |= (i < n) ? input[i] : 0;

		*output++ = B64_index_table[(int24word >> 18) & 0x3F];
        *output++ = B64_index_table[(int24word >> 12) & 0x3F];
		*output++ = ((int24word >> 6) & 0x3F) ? B64_index_table[(int24word >> 6) & 0x3F] : B64_padding;
		*output++ = (int24word & 0x3F) ? B64_index_table[int24word & 0x3F] : B64_padding;

		len += 4;
    }

	output[len] = '\0';
	return out_ptr;
}


int main()
{
	uint8_t *str = "hjhjehjehjjhpj";
	uint8_t *str2;

	str2 = B64_encode(str, strlen(str));
	printf("%s\n", str2);

	free(str2);
}