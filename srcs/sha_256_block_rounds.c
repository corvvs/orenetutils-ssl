#include "ft_ssl_sha_2_internal.h"

extern int g_is_little_endian;

static void	_print_states(const char* prefix, sha_256_word_t H[8]) {
	printf("%s %08x %08x %08x %08x %08x %08x %08x %08x\n", prefix,
		H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]
	);
}

static void	_print_x(unsigned int X[16]) {
	for (size_t i = 0; i < 16; i++) {
		printf("%08x ", X[i]);
	}
	printf("\n");
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
	_print_x(state->schedule.X);

	sha_256_word_t
		a = state->H[0],
		b = state->H[1],
		c = state->H[2],
		d = state->H[3],
		e = state->H[4],
		f = state->H[5],
		g = state->H[6],
		h = state->H[7];

    _print_states("[*H]", (sha_256_word_t[]){a, b, c, d, e, f, g, h});
	for (size_t i = 0; i < 64; ++i) {
		OPE(a, b, c, d, e, f, g, h, state->schedule.W, i);
		printf("%zu: ", i);
        _print_states("[#H]", (sha_256_word_t[]){a, b, c, d, e, f, g, h});
	}

	state->H[0] += a;
	state->H[1] += b;
	state->H[2] += c;
	state->H[3] += d;
	state->H[4] += e;
	state->H[5] += f;
	state->H[6] += g;
	state->H[7] += h;

	_print_states("[@H]", state->H);
}
