#include "ft_ssl_md5_internal.h"

extern int g_is_little_endian;

#define OF(a, b, c, d, k, s, i)	OPE(state->X, F, state->a, state->b, state->c, state->d, k, s, i)
#define OG(a, b, c, d, k, s, i)	OPE(state->X, G, state->a, state->b, state->c, state->d, k, s, i)
#define OH(a, b, c, d, k, s, i)	OPE(state->X, H, state->a, state->b, state->c, state->d, k, s, i)
#define OI(a, b, c, d, k, s, i)	OPE(state->X, I, state->a, state->b, state->c, state->d, k, s, i)

static void	_print_states(const char* prefix, md5_word_t abcd[5]) {
	dprintf(2, "%s %08x | %08x %08x %08x %08x\n", prefix, abcd[0], abcd[1], abcd[2], abcd[3], abcd[4]);
}

static void	print_states(unsigned int abcd[4]) {
	dprintf(2, "%08x %08x %08x %08x\n", abcd[0], abcd[1], abcd[2], abcd[3]);
}

void	md5_block_rounds(t_md5_state* state) {
	md5_word_t	ABCD[] = { state->A, state->B, state->C, state->D };
	print_states((unsigned int[]){ state->A, state->B, state->C, state->D });

	// X[0 ... 16] のエンディアン変換
	for (size_t i = 0; i < 16; ++i) {
		state->X[i] = PASS_LIT_END(state->X[i]);
	}

	// Round1: j = 1 .. 16
	_print_states("[0]", (md5_word_t[]){ state->X[0], state->A, state->B, state->C, state->D });
	OF(A, B, C, D,  0, 7,  0);
	_print_states("[1]", (md5_word_t[]){ state->X[0], state->A, state->B, state->C, state->D });
	OF(D, A, B, C,  1, 12,  1);
	_print_states("[2]", (md5_word_t[]){ state->X[1], state->A, state->B, state->C, state->D });
	OF(C, D, A, B,  2, 17,  2);
	_print_states("[3]", (md5_word_t[]){ state->X[2], state->A, state->B, state->C, state->D });
	OF(B, C, D, A,  3, 22,  3);
	_print_states("[3]", (md5_word_t[]){ state->X[3], state->A, state->B, state->C, state->D });
	OF(A, B, C, D,  4, 7,  4); OF(D, A, B, C,  5, 12,  5); OF(C, D, A, B,  6, 17,  6); OF(B, C, D, A,  7, 22,  7);
	OF(A, B, C, D,  8, 7,  8); OF(D, A, B, C,  9, 12,  9); OF(C, D, A, B, 10, 17, 10); OF(B, C, D, A, 11, 22, 11);
	OF(A, B, C, D, 12, 7, 12); OF(D, A, B, C, 13, 12, 13); OF(C, D, A, B, 14, 17, 14); OF(B, C, D, A, 15, 22, 15);
	_print_states("[@]", (md5_word_t[]){ state->X[15], state->A, state->B, state->C, state->D });
	// Round2: j = 17 .. 32
	OG(A, B, C, D,  1, 5, 16); OG(D, A, B, C,  6, 9, 17); OG(C, D, A, B, 11, 14, 18); OG(B, C, D, A,  0, 20, 19);
	OG(A, B, C, D,  5, 5, 20); OG(D, A, B, C, 10, 9, 21); OG(C, D, A, B, 15, 14, 22); OG(B, C, D, A,  4, 20, 23);
	OG(A, B, C, D,  9, 5, 24); OG(D, A, B, C, 14, 9, 25); OG(C, D, A, B,  3, 14, 26); OG(B, C, D, A,  8, 20, 27);
	OG(A, B, C, D, 13, 5, 28); OG(D, A, B, C,  2, 9, 29); OG(C, D, A, B,  7, 14, 30); OG(B, C, D, A, 12, 20, 31);
	_print_states("[@]", (md5_word_t[]){ state->X[12], state->A, state->B, state->C, state->D });
	// Round3: j = 33 .. 48
	OH(A, B, C, D,  5, 4, 32); OH(D, A, B, C,  8, 11, 33); OH(C, D, A, B, 11, 16, 34); OH(B, C, D, A, 14, 23, 35);
	OH(A, B, C, D,  1, 4, 36); OH(D, A, B, C,  4, 11, 37); OH(C, D, A, B,  7, 16, 38); OH(B, C, D, A, 10, 23, 39);
	OH(A, B, C, D, 13, 4, 40); OH(D, A, B, C,  0, 11, 41); OH(C, D, A, B,  3, 16, 42); OH(B, C, D, A,  6, 23, 43);
	OH(A, B, C, D,  9, 4, 44); OH(D, A, B, C, 12, 11, 45); OH(C, D, A, B, 15, 16, 46); OH(B, C, D, A,  2, 23, 47);
	_print_states("[@]", (md5_word_t[]){ state->X[2], state->A, state->B, state->C, state->D });
	// Round4: j = 49 .. 64
	OI(A, B, C, D,  0, 6, 48); OI(D, A, B, C,  7, 10, 49); OI(C, D, A, B, 14, 15, 50); OI(B, C, D, A,  5, 21, 51);
	OI(A, B, C, D, 12, 6, 52); OI(D, A, B, C,  3, 10, 53); OI(C, D, A, B, 10, 15, 54); OI(B, C, D, A,  1, 21, 55);
	OI(A, B, C, D,  8, 6, 56); OI(D, A, B, C, 15, 10, 57); OI(C, D, A, B,  6, 15, 58); OI(B, C, D, A, 13, 21, 59);
	OI(A, B, C, D,  4, 6, 60); OI(D, A, B, C, 11, 10, 61); OI(C, D, A, B,  2, 15, 62); OI(B, C, D, A,  9, 21, 63);
	_print_states("[@]", (md5_word_t[]){ state->X[9], state->A, state->B, state->C, state->D });

	state->A += ABCD[0];
	state->B += ABCD[1];
	state->C += ABCD[2];
	state->D += ABCD[3];

	print_states((unsigned int[]){ state->A, state->B, state->C, state->D });
}
