#include "ft_ssl_sha_1_rounds.h"
#include "ft_ssl_sha_1_internal.h"

extern int g_is_little_endian;

void	sha_1_block_rounds(t_sha_1_state* state) {
	/* W[0 ... 16] のエンディアン変換 */
	for (size_t i = 0; i < SHA_1_BLOCK_SIZE; ++i) {
		state->schedule.W[i] = PASS_BIG_END(state->schedule.W[i]);
	}
	/* W[16 ... ] の初期化 */
	for (size_t i = SHA_1_BLOCK_SIZE; i < SHA_1_SCHEDULE_SIZE; ++i) {
		state->schedule.W[i] = ROTL(1, 
            state->schedule.W[i-3] ^ 
            state->schedule.W[i-8] ^
			state->schedule.W[i-14] ^ 
            state->schedule.W[i-16]);
	}

	sha_1_word_t
		a = state->H[0],
		b = state->H[1],
		c = state->H[2],
		d = state->H[3],
		e = state->H[4];

	for (size_t i = 0; i < SHA_1_SCHEDULE_SIZE; ++i) {
		sha_1_word_t temp = ROTL(5, a) + F(i, b, c, d) + e + state->schedule.W[i] + SHA_1_K[i];
        e = d;
        d = c;
        c = ROTL(30, b);
        b = a;
        a = temp;
	}

	state->H[0] += a;
	state->H[1] += b;
	state->H[2] += c;
	state->H[3] += d;
	state->H[4] += e;
}