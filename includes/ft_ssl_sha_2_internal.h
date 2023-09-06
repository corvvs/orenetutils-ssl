#ifndef FT_SSL_SHA_2_INTERNAL_H
#define FT_SSL_SHA_2_INTERNAL_H

#include "ft_ssl_lib.h"
#include "ft_ssl_sha_2.h"
#include "utils_endian.h"

typedef uint32_t sha_224_word_t;
typedef uint32_t sha_256_word_t;
typedef uint64_t sha_384_word_t;
typedef uint64_t sha_512_word_t;
typedef uint64_t sha_512_224_word_t;
typedef uint64_t sha_512_256_word_t;

#define K_256 {\
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,\
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,\
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,\
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,\
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,\
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,\
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,\
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,\
}

#define K_512 {\
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,\
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,\
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,\
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,\
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,\
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,\
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,\
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL, 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,\
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,\
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,\
}

static const sha_224_word_t SHA_224_K[64] = K_256;
static const sha_256_word_t SHA_256_K[64] = K_256;
static const sha_384_word_t SHA_384_K[80] = K_512;
static const sha_512_word_t SHA_512_K[80] = K_512;
static const sha_512_224_word_t SHA_512_224_K[80] = K_512;
static const sha_512_256_word_t SHA_512_256_K[80] = K_512;

#define SHA_224_STATE_SIZE 8
#define SHA_256_STATE_SIZE 8
#define SHA_384_STATE_SIZE 8
#define SHA_512_STATE_SIZE 8
#define SHA_512_224_STATE_SIZE 8
#define SHA_512_256_STATE_SIZE 8

static const sha_224_word_t SHA_224_H0[SHA_224_STATE_SIZE] = {
    0xc1059ed8,
    0x367cd507,
    0x3070dd17,
    0xf70e5939,
    0xffc00b31,
    0x68581511,
    0x64f98fa7,
    0xbefa4fa4,
};

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

static const sha_384_word_t SHA_384_H0[SHA_384_STATE_SIZE] = {
	0xcbbb9d5dc1059ed8ULL,
	0x629a292a367cd507ULL,
	0x9159015a3070dd17ULL,
	0x152fecd8f70e5939ULL,
	0x67332667ffc00b31ULL,
	0x8eb44a8768581511ULL,
	0xdb0c2e0d64f98fa7ULL,
	0x47b5481dbefa4fa4ULL,
};

static const sha_512_word_t SHA_512_H0[SHA_512_STATE_SIZE] = {
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL,
};

static const sha_512_224_word_t SHA_512_224_H0[SHA_512_224_STATE_SIZE] = {
	0x8C3D37C819544DA2ull,
	0x73E1996689DCD4D6ull,
	0x1DFAB7AE32FF9C82ull,
	0x679DD514582F9FCFull,
	0x0F6D2B697BD44DA8ull,
	0x77E36F7304C48942ull,
	0x3F9D85A86A1D36C8ull,
	0x1112E6AD91D692A1ull,
};

static const sha_512_256_word_t SHA_512_256_H0[SHA_512_256_STATE_SIZE] = {
	0x22312194FC2BF72Cull,
	0x9F555FA3C84C64C2ull,
	0x2393B86B6F53B151ull,
	0x963877195940EABDull,
	0x96283EE2A88EFFE3ull,
	0xBE5E1E2553863992ull,
	0x2B0199FC2C85B8AAull,
	0x0EB72DDC81C52CA2ull,
};

#define SHA_224_WORD_BIT_SIZE (sizeof(sha_224_word_t) * OCTET_BIT_SIZE)
#define SHA_224_ONE_PADDING_BIT_LEN(len) (len + 1)
#define SHA_224_ZERO_PADDING_BIT_LEN(len) (SHA_224_ONE_PADDING_BIT_LEN(len) + SHA_224_ZERO_PADDING_BIT_SIZE(SHA_224_ONE_PADDING_BIT_LEN(len)))
#define SHA_224_ZERO_PADDING_BIT_SIZE(len) (-(len + sizeof(uint64_t) * OCTET_BIT_SIZE) % SHA_224_WORD_BLOCK_BIT_SIZE)
#define SHA_224_PADDING_BIT_LEN(len) (SHA_224_ZERO_PADDING_BIT_LEN(len) + sizeof(uint64_t) * OCTET_BIT_SIZE)

#define SHA_256_WORD_BIT_SIZE (sizeof(sha_256_word_t) * OCTET_BIT_SIZE)
#define SHA_256_ONE_PADDING_BIT_LEN(len) (len + 1)
#define SHA_256_ZERO_PADDING_BIT_LEN(len) (SHA_256_ONE_PADDING_BIT_LEN(len) + SHA_256_ZERO_PADDING_BIT_SIZE(SHA_256_ONE_PADDING_BIT_LEN(len)))
#define SHA_256_ZERO_PADDING_BIT_SIZE(len) (-(len + sizeof(uint64_t) * OCTET_BIT_SIZE) % SHA_256_WORD_BLOCK_BIT_SIZE)
#define SHA_256_PADDING_BIT_LEN(len) (SHA_256_ZERO_PADDING_BIT_LEN(len) + sizeof(uint64_t) * OCTET_BIT_SIZE)

#define SHA_384_WORD_BIT_SIZE (sizeof(sha_384_word_t) * OCTET_BIT_SIZE)
#define SHA_384_ONE_PADDING_BIT_LEN(len) (len + 1)
#define SHA_384_ZERO_PADDING_BIT_LEN(len) (SHA_384_ONE_PADDING_BIT_LEN(len) + SHA_384_ZERO_PADDING_BIT_SIZE(SHA_384_ONE_PADDING_BIT_LEN(len)))
#define SHA_384_ZERO_PADDING_BIT_SIZE(len) (-(len + sizeof(uint64_t) * OCTET_BIT_SIZE) % SHA_384_WORD_BLOCK_BIT_SIZE)
#define SHA_384_PADDING_BIT_LEN(len) (SHA_384_ZERO_PADDING_BIT_LEN(len) + sizeof(uint64_t) * OCTET_BIT_SIZE)

#define SHA_512_WORD_BIT_SIZE (sizeof(sha_512_word_t) * OCTET_BIT_SIZE)
#define SHA_512_ONE_PADDING_BIT_LEN(len) (len + 1)
#define SHA_512_ZERO_PADDING_BIT_LEN(len) (SHA_512_ONE_PADDING_BIT_LEN(len) + SHA_512_ZERO_PADDING_BIT_SIZE(SHA_512_ONE_PADDING_BIT_LEN(len)))
#define SHA_512_ZERO_PADDING_BIT_SIZE(len) (-(len + sizeof(uint64_t) * OCTET_BIT_SIZE) % SHA_512_WORD_BLOCK_BIT_SIZE)
#define SHA_512_PADDING_BIT_LEN(len) (SHA_512_ZERO_PADDING_BIT_LEN(len) + sizeof(uint64_t) * OCTET_BIT_SIZE)

#define SHA_512_256_WORD_BIT_SIZE (sizeof(sha_512_256_word_t) * OCTET_BIT_SIZE)
#define SHA_512_256_ONE_PADDING_BIT_LEN(len) (len + 1)
#define SHA_512_256_ZERO_PADDING_BIT_LEN(len) (SHA_512_256_ONE_PADDING_BIT_LEN(len) + SHA_512_256_ZERO_PADDING_BIT_SIZE(SHA_512_256_ONE_PADDING_BIT_LEN(len)))
#define SHA_512_256_ZERO_PADDING_BIT_SIZE(len) (-(len + sizeof(uint64_t) * OCTET_BIT_SIZE) % SHA_512_256_WORD_BLOCK_BIT_SIZE)
#define SHA_512_256_PADDING_BIT_LEN(len) (SHA_512_256_ZERO_PADDING_BIT_LEN(len) + sizeof(uint64_t) * OCTET_BIT_SIZE)

typedef struct s_sha_224_state
{
	const uint8_t *message;
	const uint64_t message_len;
	const uint64_t message_1bp_len;
	const uint64_t message_0bp_len;
	const uint64_t padded_message_len;
	uint64_t block_from;

	sha_224_word_t H[SHA_224_STATE_SIZE];
	union {
		sha_224_word_t W[16 * 4];
		sha_224_word_t X[16];
	} schedule;
} t_sha_224_state;

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

typedef struct s_sha_384_state
{
	const uint8_t *message;
	const uint64_t message_len;
	const uint64_t message_1bp_len;
	const uint64_t message_0bp_len;
	const uint64_t padded_message_len;
	uint64_t block_from;

	sha_384_word_t H[SHA_384_STATE_SIZE];
	union {
		sha_384_word_t W[16 * 5];
		sha_384_word_t X[16];
	} schedule;
} t_sha_384_state;

typedef struct s_sha_512_state
{
	const uint8_t *message;
	const uint64_t message_len;
	const uint64_t message_1bp_len;
	const uint64_t message_0bp_len;
	const uint64_t padded_message_len;
	uint64_t block_from;

	sha_512_word_t H[SHA_512_STATE_SIZE];
	union {
		sha_512_word_t W[16 * 5];
		sha_512_word_t X[16];
	} schedule;
} t_sha_512_state;

typedef struct s_sha_512_256_state
{
	const uint8_t *message;
	const uint64_t message_len;
	const uint64_t message_1bp_len;
	const uint64_t message_0bp_len;
	const uint64_t padded_message_len;
	uint64_t block_from;

	sha_512_256_word_t H[SHA_512_256_STATE_SIZE];
	union {
		sha_512_256_word_t W[16 * 5];
		sha_512_256_word_t X[16];
	} schedule;
} t_sha_512_256_state;

#define SHA_224_INITIAL_STATE(message, message_len) ((t_sha_224_state){ \
	.message = message,                                                 \
	.message_len = message_len,                                         \
	.message_1bp_len = SHA_224_ONE_PADDING_BIT_LEN(message_len),        \
	.message_0bp_len = SHA_224_ZERO_PADDING_BIT_LEN(message_len),       \
	.padded_message_len = SHA_224_PADDING_BIT_LEN(message_len),         \
	.block_from = 0,                                                    \
})

#define SHA_256_INITIAL_STATE(message, message_len) ((t_sha_256_state){ \
	.message = message,                                                 \
	.message_len = message_len,                                         \
	.message_1bp_len = SHA_256_ONE_PADDING_BIT_LEN(message_len),        \
	.message_0bp_len = SHA_256_ZERO_PADDING_BIT_LEN(message_len),       \
	.padded_message_len = SHA_256_PADDING_BIT_LEN(message_len),         \
	.block_from = 0,                                                    \
})

#define SHA_384_INITIAL_STATE(message, message_len) ((t_sha_384_state){ \
	.message = message,                                                 \
	.message_len = message_len,                                         \
	.message_1bp_len = SHA_384_ONE_PADDING_BIT_LEN(message_len),        \
	.message_0bp_len = SHA_384_ZERO_PADDING_BIT_LEN(message_len),       \
	.padded_message_len = SHA_384_PADDING_BIT_LEN(message_len),         \
	.block_from = 0,                                                    \
})

#define SHA_512_INITIAL_STATE(message, message_len) ((t_sha_512_state){ \
	.message = message,                                                 \
	.message_len = message_len,                                         \
	.message_1bp_len = SHA_512_ONE_PADDING_BIT_LEN(message_len),        \
	.message_0bp_len = SHA_512_ZERO_PADDING_BIT_LEN(message_len),       \
	.padded_message_len = SHA_512_PADDING_BIT_LEN(message_len),         \
	.block_from = 0,                                                    \
})

#define SHA_512_256_INITIAL_STATE(message, message_len) ((t_sha_512_256_state){ \
	.message = message,                                                 \
	.message_len = message_len,                                         \
	.message_1bp_len = SHA_512_256_ONE_PADDING_BIT_LEN(message_len),        \
	.message_0bp_len = SHA_512_256_ZERO_PADDING_BIT_LEN(message_len),       \
	.padded_message_len = SHA_512_256_PADDING_BIT_LEN(message_len),         \
	.block_from = 0,                                                    \
})

// sha_256_block_padding.c
void	sha_256_block_padding(t_sha_256_state* state);

// sha_256_block_rounds.c
void	sha_256_block_rounds(t_sha_256_state* state);

// sha_256_derive_digest.c
t_sha_256_digest	sha_256_derive_digest(const t_sha_256_state* state);

// sha_224_block_padding.c
void	sha_224_block_padding(t_sha_224_state* state);

// sha_224_block_rounds.c
void	sha_224_block_rounds(t_sha_224_state* state);

// sha_224_derive_digest.c
t_sha_224_digest	sha_224_derive_digest(const t_sha_224_state* state);

// sha_384_block_padding.c
void	sha_384_block_padding(t_sha_384_state* state);

// sha_384_block_rounds.c
void	sha_384_block_rounds(t_sha_384_state* state);

// sha_384_derive_digest.c
t_sha_384_digest	sha_384_derive_digest(const t_sha_384_state* state);

// sha_512_block_padding.c
void	sha_512_block_padding(t_sha_512_state* state);

// sha_512_block_rounds.c
void	sha_512_block_rounds(t_sha_512_state* state);

// sha_512_derive_digest.c
t_sha_512_digest	sha_512_derive_digest(const t_sha_512_state* state);

// sha_512_256_block_padding.c
void	sha_512_256_block_padding(t_sha_512_256_state* state);

// sha_512_256_block_rounds.c
void	sha_512_256_block_rounds(t_sha_512_256_state* state);

// sha_512_256_derive_digest.c
t_sha_512_256_digest	sha_512_256_derive_digest(const t_sha_512_256_state* state);

#endif
