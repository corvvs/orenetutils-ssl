#ifndef FT_SSL_SHA_2_H
#define FT_SSL_SHA_2_H

#include "ft_ssl_lib.h"

#define SHA_256_WORD_BLOCK_BIT_SIZE 512
#define SHA_256_DIGEST_BIT_SIZE (SHA_256_WORD_BLOCK_BIT_SIZE / 2)

#define SHA_224_WORD_BLOCK_BIT_SIZE SHA_256_WORD_BLOCK_BIT_SIZE
#define SHA_224_DIGEST_BIT_SIZE ((SHA_224_WORD_BLOCK_BIT_SIZE / 2) - 32)

#define SHA_512_WORD_BLOCK_BIT_SIZE 1024
#define SHA_512_DIGEST_BIT_SIZE (SHA_512_WORD_BLOCK_BIT_SIZE / 2)


typedef struct s_sha_256_digest
{
	uint8_t digest[SHA_256_DIGEST_BIT_SIZE / OCTET_BIT_SIZE];
} t_sha_256_digest;

typedef struct s_sha_224_digest
{
	uint8_t digest[SHA_224_DIGEST_BIT_SIZE / OCTET_BIT_SIZE];
} t_sha_224_digest;

typedef struct s_sha_512_digest
{
	uint8_t digest[SHA_512_DIGEST_BIT_SIZE / OCTET_BIT_SIZE];
} t_sha_512_digest;

typedef union u_bit_size {
	struct {
		uint32_t	little;
		uint32_t	big;
	}			s_32;
	uint64_t	s_64;
}	t_bit_size;

#endif
