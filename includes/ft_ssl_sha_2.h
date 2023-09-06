#ifndef FT_SSL_SHA_2_H
#define FT_SSL_SHA_2_H

#include "ft_ssl_lib.h"

#define SHA_224_WORD_BLOCK_BIT_SIZE 512
#define SHA_224_DIGEST_BIT_SIZE ((SHA_224_WORD_BLOCK_BIT_SIZE / 2) - 32)

#define SHA_256_WORD_BLOCK_BIT_SIZE 512
#define SHA_256_DIGEST_BIT_SIZE (SHA_256_WORD_BLOCK_BIT_SIZE / 2)

#define SHA_384_WORD_BLOCK_BIT_SIZE 1024
#define SHA_384_DIGEST_BIT_SIZE ((SHA_384_WORD_BLOCK_BIT_SIZE / 2) - 128)

#define SHA_512_WORD_BLOCK_BIT_SIZE 1024
#define SHA_512_DIGEST_BIT_SIZE (SHA_512_WORD_BLOCK_BIT_SIZE / 2)

#define SHA_512_256_WORD_BLOCK_BIT_SIZE SHA_512_WORD_BLOCK_BIT_SIZE
#define SHA_512_256_DIGEST_BIT_SIZE SHA_256_DIGEST_BIT_SIZE

#define SHA_512_224_WORD_BLOCK_BIT_SIZE SHA_512_WORD_BLOCK_BIT_SIZE
#define SHA_512_224_DIGEST_BIT_SIZE SHA_224_DIGEST_BIT_SIZE

// SHA-2ファミリーのダイジェスト構造体を定義するマクロ
#define define_sha_2_digest_struct(Subtype)\
typedef struct s_sha_##Subtype##_digest\
{\
	uint8_t digest[SHA_##Subtype##_DIGEST_BIT_SIZE / OCTET_BIT_SIZE];\
} t_sha_##Subtype##_digest;

define_sha_2_digest_struct(224);
define_sha_2_digest_struct(256);
define_sha_2_digest_struct(384);
define_sha_2_digest_struct(512);
define_sha_2_digest_struct(512_224);
define_sha_2_digest_struct(512_256);

typedef union u_bit_size {
	struct {
		uint32_t	little;
		uint32_t	big;
	}			s_32;
	uint64_t	s_64;
}	t_bit_size;

#endif
