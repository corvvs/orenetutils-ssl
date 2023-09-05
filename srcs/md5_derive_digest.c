#include "ft_ssl_md5_internal.h"

extern int g_is_little_endian;

t_md5_digest	md5_derive_digest(const t_md5_state* state) {
	t_md5_digest	digest = {};
	md5_word_t	ABCD[] = { state->A, state->B, state->C, state->D };
	size_t		digest_index = 0;
	for (size_t i = 0; i < sizeof(ABCD) / sizeof(md5_word_t); ++i) {
		ABCD[i] = PASS_LIT_END(ABCD[i]);
		for (size_t j = 0; j < sizeof(md5_word_t); ++j) {
			digest.digest[digest_index] = ABCD[i] % 256;
			ABCD[i] /= 256;
			digest_index += 1;
		}
	}
	return digest;
}
