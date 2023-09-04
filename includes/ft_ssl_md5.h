#ifndef FT_SSL_MD5_H
#define FT_SSL_MD5_H

#include "ft_ssl_lib.h"

#define OCTET_BIT_SIZE 8
#define MD5_WORD_BLOCK_BIT_SIZE 512
#define MD5_DIGEST_BIT_SIZE (MD5_WORD_BLOCK_BIT_SIZE / 4)

typedef struct s_md5_digest
{
	uint8_t digest[MD5_DIGEST_BIT_SIZE / OCTET_BIT_SIZE];
} t_md5_digest;

#endif