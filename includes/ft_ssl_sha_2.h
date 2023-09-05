#ifndef FT_SSL_SHA_2_H
#define FT_SSL_SHA_2_H

#include "ft_ssl_lib.h"

#define SHA_2_WORD_BLOCK_BIT_SIZE 512
#define SHA_2_DIGEST_BIT_SIZE (SHA_2_WORD_BLOCK_BIT_SIZE / 2)

typedef struct s_sha_256_digest
{
	uint8_t digest[SHA_2_DIGEST_BIT_SIZE / OCTET_BIT_SIZE];
} t_sha_256_digest;

#endif
