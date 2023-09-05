#ifndef FT_SSL_MD5_INTERNAL_H
#define FT_SSL_MD5_INTERNAL_H

#include "ft_ssl_lib.h"
#include "ft_ssl_md5.h"
#include "utils_endian.h"

typedef uint32_t md5_word_t;

static const md5_word_t MD5_T[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

#define A0 0x67452301u
#define B0 0xefcdab89u
#define C0 0x98badcfeu
#define D0 0x10325476u

#define MD5_WORD_BIT_SIZE (sizeof(md5_word_t) * OCTET_BIT_SIZE)
#define MD5_ONE_PADDING_BIT_LEN(len) (len + 1)
#define MD5_ZERO_PADDING_BIT_LEN(len) (MD5_ONE_PADDING_BIT_LEN(len) + MD5_ZERO_PADDING_BIT_SIZE(MD5_ONE_PADDING_BIT_LEN(len)))
#define MD5_ZERO_PADDING_BIT_SIZE(len) (-(len + sizeof(uint64_t) * OCTET_BIT_SIZE) % MD5_WORD_BLOCK_BIT_SIZE)
#define MD5_PADDING_BIT_LEN(len) (MD5_ZERO_PADDING_BIT_LEN(len) + sizeof(uint64_t) * OCTET_BIT_SIZE)

#define F(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))
#define G(X, Y, Z) (((X) & (Z)) | ((Y) & (~Z)))
#define H(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define I(X, Y, Z) ((Y) ^ ((X) | (~Z)))
#define ROTL(n, x) (((x) << (n)) | ((x) >> (MD5_WORD_BIT_SIZE - (n))))

// printf("(%08x, %08x, %08x, %08x : %08x, %u, %08x)\n", a, b, c, d, X[k], s, MD5_T[i]);

#define OPE(X, Batch, a, b, c, d, k, s, i) {\
	a += Batch(b, c, d) + X[k] + MD5_T[i];\
	a = ROTL(s, a);\
	a += b;\
}

typedef struct s_md5_state
{
	const uint8_t *message;
	const uint64_t message_len;
	const uint64_t message_1bp_len;
	const uint64_t message_0bp_len;
	const uint64_t padded_message_len;
	uint64_t block_from;

	md5_word_t A;
	md5_word_t B;
	md5_word_t C;
	md5_word_t D;
	md5_word_t X[MD5_WORD_BLOCK_BIT_SIZE / MD5_WORD_BIT_SIZE];
} t_md5_state;

#define MD5_INITIAL_STATE(message, message_len) ((t_md5_state){ \
	.message = message,                                         \
	.message_len = message_len,                                 \
	.message_1bp_len = MD5_ONE_PADDING_BIT_LEN(message_len),    \
	.message_0bp_len = MD5_ZERO_PADDING_BIT_LEN(message_len),   \
	.padded_message_len = MD5_PADDING_BIT_LEN(message_len),     \
	.block_from = 0,                                            \
	.A = A0,                                                    \
	.B = B0,                                                    \
	.C = C0,                                                    \
	.D = D0,                                                    \
})

// md5_block_padding.c
void	md5_block_padding(t_md5_state *state);

// md5_block_rounds.c
void	md5_block_rounds(t_md5_state* state);

// md5_derive_digest.c
t_md5_digest	md5_derive_digest(const t_md5_state* state);

#endif
