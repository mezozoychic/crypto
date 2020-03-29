#include <stdio.h>
#include <inttypes.h>
#include <string.h>

uint8_t B64[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                  'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

                    
uint8_t B64_padding = '=';

void B64_encode(uint8_t *input, uint8_t *output)
{
    uint32_t int24word;
    unsigned len = 0;

    while (*input)
    {
        int24word = *input++ << 0x10;
		int24word |= *input ? (*input++ << 0x08) : 0;
		int24word |= *input ? *input++ : 0;

		*output++ = B64[(int24word >> 18) & 0x3F];
        *output++ = B64[(int24word >> 12) & 0x3F];
		*output++ = ((int24word >> 6) & 0x3F) ? B64[(int24word >> 6) & 0x3F] : B64_padding;
		*output++ = (int24word & 0x3F) ? B64[int24word & 0x3F] : B64_padding;

		len += 4;
    }

	output[len] = '\0';
}

int main()
{
	uint8_t *str = "tjsrkrykdtylk";
	uint8_t str2[128];

	B64_encode(str, str2);
	printf("%s\n", str2);
}