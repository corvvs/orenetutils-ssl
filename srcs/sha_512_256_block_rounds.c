#include "ft_ssl_sha_512_rounds.h"
#include "ft_ssl_sha_2_internal.h"

extern int g_is_little_endian;

void	sha_512_256_block_rounds(t_sha_512_256_state* state) {
	// W[0 ... 16] のエンディアン変換
	for (size_t i = 0; i < 16; ++i) {
		state->schedule.W[i] = PASS_BIG_END(state->schedule.W[i]);
	}
	// W[16 ... 80] の初期化
	for (size_t i = 16; i < 80; ++i) {
		state->schedule.W[i] =
			SSIG1(state->schedule.W[i-2]) + state->schedule.W[i-7] +
			SSIG0(state->schedule.W[i-15]) + state->schedule.W[i-16];
	}

	sha_512_256_word_t
		a = state->H[0],
		b = state->H[1],
		c = state->H[2],
		d = state->H[3],
		e = state->H[4],
		f = state->H[5],
		g = state->H[6],
		h = state->H[7];

	for (size_t i = 0; i < 80; ++i) {
		OPE(512_256, a, b, c, d, e, f, g, h, state->schedule.W, i);
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
