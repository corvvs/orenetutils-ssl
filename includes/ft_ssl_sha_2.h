#ifndef FT_SSL_SHA_256_H
#define FT_SSL_SHA_256_H

#include "ft_ssl_lib.h"

#define SHA_256_WORD_BLOCK_BIT_SIZE 512
#define SHA_256_DIGEST_BIT_SIZE (SHA_256_WORD_BLOCK_BIT_SIZE / 2)

typedef struct s_sha_256_digest
{
	uint8_t digest[SHA_256_DIGEST_BIT_SIZE / OCTET_BIT_SIZE];
} t_sha_256_digest;

#endif
