#ifndef FT_SSL_SHA_1_H
#define FT_SSL_SHA_1_H

#include "ft_ssl_lib.h"

#define SHA_1_WORD_BLOCK_BIT_SIZE 512
#define SHA_1_DIGEST_BIT_SIZE 160

typedef struct s_sha_1_digest
{
	uint8_t digest[SHA_1_DIGEST_BIT_SIZE / OCTET_BIT_SIZE];
} t_sha_1_digest;

#endif
