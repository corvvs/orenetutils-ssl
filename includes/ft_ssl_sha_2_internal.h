#ifndef FT_SSL_SHA_2_INTERNAL_H
#define FT_SSL_SHA_2_INTERNAL_H

#include "ft_ssl_lib.h"
#include "ft_ssl_sha_2.h"
#include "utils_endian.h"

typedef uint32_t sha_256_word_t;

static const sha_256_word_t SHA_256_K[64] = {
	0x428a2f98,
	0x71374491,
	0xb5c0fbcf,
	0xe9b5dba5,
	0x3956c25b,
	0x59f111f1,
	0x923f82a4,
	0xab1c5ed5,
	0xd807aa98,
	0x12835b01,
	0x243185be,
	0x550c7dc3,
	0x72be5d74,
	0x80deb1fe,
	0x9bdc06a7,
	0xc19bf174,
	0xe49b69c1,
	0xefbe4786,
	0x0fc19dc6,
	0x240ca1cc,
	0x2de92c6f,
	0x4a7484aa,
	0x5cb0a9dc,
	0x76f988da,
	0x983e5152,
	0xa831c66d,
	0xb00327c8,
	0xbf597fc7,
	0xc6e00bf3,
	0xd5a79147,
	0x06ca6351,
	0x14292967,
	0x27b70a85,
	0x2e1b2138,
	0x4d2c6dfc,
	0x53380d13,
	0x650a7354,
	0x766a0abb,
	0x81c2c92e,
	0x92722c85,
	0xa2bfe8a1,
	0xa81a664b,
	0xc24b8b70,
	0xc76c51a3,
	0xd192e819,
	0xd6990624,
	0xf40e3585,
	0x106aa070,
	0x19a4c116,
	0x1e376c08,
	0x2748774c,
	0x34b0bcb5,
	0x391c0cb3,
	0x4ed8aa4a,
	0x5b9cca4f,
	0x682e6ff3,
	0x748f82ee,
	0x78a5636f,
	0x84c87814,
	0x8cc70208,
	0x90befffa,
	0xa4506ceb,
	0xbef9a3f7,
	0xc67178f2,
};

#define SHA_256_STATE_SIZE 8

static const sha_256_word_t SHA_256_H0[SHA_256_STATE_SIZE] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
};

#define SHA_256_WORD_BIT_SIZE (sizeof(sha_256_word_t) * OCTET_BIT_SIZE)
#define SHA_256_ONE_PADDING_BIT_LEN(len) (len + 1)
#define SHA_256_ZERO_PADDING_BIT_LEN(len) (SHA_256_ONE_PADDING_BIT_LEN(len) + SHA_256_ZERO_PADDING_BIT_SIZE(SHA_256_ONE_PADDING_BIT_LEN(len)))
#define SHA_256_ZERO_PADDING_BIT_SIZE(len) (-(len + sizeof(uint64_t) * OCTET_BIT_SIZE) % SHA_2_WORD_BLOCK_BIT_SIZE)
#define SHA_256_PADDING_BIT_LEN(len) (SHA_256_ZERO_PADDING_BIT_LEN(len) + sizeof(uint64_t) * OCTET_BIT_SIZE)

#define SHR(n, x) ((x) >> (n))
#define ROTR(n, x) (((x) >> (n)) | ((x) << (SHA_256_WORD_BIT_SIZE - (n))))
#define ROTL(n, x) (((x) << (n)) | ((x) >> (SHA_256_WORD_BIT_SIZE - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))
#define BSIG1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))
#define SSIG0(x) (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x))
#define SSIG1(x) (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x))

#define OPE(a, b, c, d, e, f, g, h, W, i)     \
	{                                         \
		sha_256_word_t T1 = h + BSIG1(e) + CH(e, f, g) + SHA_256_K[i] + W[i]; \
		sha_256_word_t T2 = BSIG0(a) + MAJ(a, b, c); \
		h = g;\
		g = f;\
		f = e;\
		e = d + T1;\
		d = c;\
		c = b;\
		b = a;\
		a = T1 + T2;\
	}

typedef struct s_sha_256_state
{
	const uint8_t *message;
	const uint64_t message_len;
	const uint64_t message_1bp_len;
	const uint64_t message_0bp_len;
	const uint64_t padded_message_len;
	uint64_t block_from;

	sha_256_word_t H[SHA_256_STATE_SIZE];
	union {
		sha_256_word_t W[16 * 4];
		sha_256_word_t X[16];
	} schedule;
} t_sha_256_state;

#define SHA_256_INITIAL_STATE(message, message_len) ((t_sha_256_state){ \
	.message = message,                                           \
	.message_len = message_len,                                   \
	.message_1bp_len = SHA_256_ONE_PADDING_BIT_LEN(message_len),    \
	.message_0bp_len = SHA_256_ZERO_PADDING_BIT_LEN(message_len),   \
	.padded_message_len = SHA_256_PADDING_BIT_LEN(message_len),     \
	.block_from = 0,                                              \
})

// sha_256_block_padding.c
void	sha_256_block_padding(t_sha_256_state* state);

// sha_256_block_rounds.c
void	sha_256_block_rounds(t_sha_256_state* state);

#endif
