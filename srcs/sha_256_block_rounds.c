#include "ft_ssl_sha_2_internal.h"

extern int g_is_little_endian;

#define SHR(n, x) ((x) >> (n))
#define ROTR(n, x) (((x) >> (n)) | ((x) << (SHA_256_WORD_BIT_SIZE - (n))))
#define ROTL(n, x) (((x) << (n)) | ((x) >> (SHA_256_WORD_BIT_SIZE - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))
#define BSIG1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))
#define SSIG0(x) (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x))
#define SSIG1(x) (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x))

#define OPE(a, b, c, d, e, f, g, h, W, i)     \
	{                                         \
		sha_256_word_t T1 = h + BSIG1(e) + CH(e, f, g) + SHA_256_K[i] + W[i]; \
		sha_256_word_t T2 = BSIG0(a) + MAJ(a, b, c); \
		h = g;\
		g = f;\
		f = e;\
		e = d + T1;\
		d = c;\
		c = b;\
		b = a;\
		a = T1 + T2;\
	}

void	sha_256_block_rounds(t_sha_256_state* state) {
	// W[0 ... 16] のエンディアン変換
	for (size_t i = 0; i < 16; ++i) {
		state->schedule.W[i] = PASS_BIG_END(state->schedule.W[i]);
	}
	// W[16 ... 64] の初期化
	for (size_t i = 16; i < 64; ++i) {
		state->schedule.W[i] =
			SSIG1(state->schedule.W[i-2]) + state->schedule.W[i-7] +
			SSIG0(state->schedule.W[i-15]) + state->schedule.W[i-16];
	}

	sha_256_word_t
		a = state->H[0],
		b = state->H[1],
		c = state->H[2],
		d = state->H[3],
		e = state->H[4],
		f = state->H[5],
		g = state->H[6],
		h = state->H[7];

	for (size_t i = 0; i < 64; ++i) {
		OPE(a, b, c, d, e, f, g, h, state->schedule.W, i);
	}

	state->H[0] += a;
	state->H[1] += b;
	state->H[2] += c;
	state->H[3] += d;
	state->H[4] += e;
	state->H[5] += f;
	state->H[6] += g;
	state->H[7] += h;
}
