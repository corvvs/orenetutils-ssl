#ifndef FT_SSL_SHA_256_ROUNDS_H
#define FT_SSL_SHA_256_ROUNDS_H

// SHA-256系(256, 224)のブロック演算

#define SHR(n, x) ((x) >> (n))
#define ROTR(n, x) (((x) >> (n)) | ((x) << (SHA_256_WORD_BIT_SIZE - (n))))
#define ROTL(n, x) (((x) << (n)) | ((x) >> (SHA_256_WORD_BIT_SIZE - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))
#define BSIG1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))
#define SSIG0(x) (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x))
#define SSIG1(x) (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x))

#endif
