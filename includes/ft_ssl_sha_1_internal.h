#ifndef FT_SSL_SHA_1_INTERNAL_H
#define FT_SSL_SHA_1_INTERNAL_H

#include "ft_ssl_lib.h"
#include "ft_ssl_sha_1.h"
#include "utils_endian.h"

typedef uint32_t sha_1_word_t;

#define K_2560 {\
	0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999,\
	0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999,\
	0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1,\
	0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1,\
	0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC,\
	0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC,\
	0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6,\
	0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6,\
}

static const sha_1_word_t SHA_1_K[80] = K_2560;

#define SHA_1_STATE_SIZE 5

#define SHA_1_BLOCK_SIZE 16

#define SHA_1_SCHEDULE_SIZE 80

static const sha_1_word_t SHA_1_H0[SHA_1_STATE_SIZE] = {
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
};

#define SHA_1_WORD_BIT_SIZE (sizeof(sha_1_word_t) * OCTET_BIT_SIZE)
#define SHA_1_ONE_PADDING_BIT_LEN(len) (len + 1)
#define SHA_1_ZERO_PADDING_BIT_LEN(len) (SHA_1_ONE_PADDING_BIT_LEN(len) + SHA_1_ZERO_PADDING_BIT_SIZE(SHA_1_ONE_PADDING_BIT_LEN(len)))
#define SHA_1_ZERO_PADDING_BIT_SIZE(len) (-(len + sizeof(uint64_t) * OCTET_BIT_SIZE) % SHA_1_WORD_BLOCK_BIT_SIZE)
#define SHA_1_PADDING_BIT_LEN(len) (SHA_1_ZERO_PADDING_BIT_LEN(len) + sizeof(uint64_t) * OCTET_BIT_SIZE)


typedef struct s_sha_1_state
{
	const uint8_t *message;
	const uint64_t message_len;
	const uint64_t message_1bp_len;
	const uint64_t message_0bp_len;
	const uint64_t padded_message_len;
	uint64_t block_from;

	sha_1_word_t H[SHA_1_STATE_SIZE];
	union {
		sha_1_word_t W[SHA_1_SCHEDULE_SIZE];
		uint64_t X[SHA_1_BLOCK_SIZE];
	} schedule;
} t_sha_1_state;

// SHA-1ファミリーの初期内部状態を返すマクロ
#define SHA_1_INITIAL_STATE(message, message_len) ((t_sha_1_state){ \
	.message = message,                                                 \
	.message_len = message_len,                                         \
	.message_1bp_len = SHA_1_ONE_PADDING_BIT_LEN(message_len),        \
	.message_0bp_len = SHA_1_ZERO_PADDING_BIT_LEN(message_len),       \
	.padded_message_len = SHA_1_PADDING_BIT_LEN(message_len),         \
	.block_from = 0,                                                    \
})

void	sha_1_block_padding(t_sha_1_state* state);
void	sha_1_block_rounds(t_sha_1_state* state);
t_sha_1_digest	sha_1_derive_digest(const t_sha_1_state* state);

#endif
