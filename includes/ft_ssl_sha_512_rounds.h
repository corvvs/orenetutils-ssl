#ifndef FT_SSL_SHA_512_ROUNDS_H
#define FT_SSL_SHA_512_ROUNDS_H

// SHA-512系(512, 384, 512/224, 512/256のブロック演算

#define SHR(n, x) ((x) >> (n))
#define ROTR(n, x) (((x) >> (n)) | ((x) << (SHA_512_WORD_BIT_SIZE - (n))))
#define ROTL(n, x) (((x) << (n)) | ((x) >> (SHA_512_WORD_BIT_SIZE - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(28, x) ^ ROTR(34, x) ^ ROTR(39, x))
#define BSIG1(x) (ROTR(14, x) ^ ROTR(18, x) ^ ROTR(41, x))
#define SSIG0(x) (ROTR(1, x) ^ ROTR(8, x) ^ SHR(7, x))
#define SSIG1(x) (ROTR(19, x) ^ ROTR(61, x) ^ SHR(6, x))

#endif
