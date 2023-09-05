#include "ft_ssl_sha_2_internal.h"

extern int g_is_little_endian;

t_sha_256_digest	sha_256_derive_digest(const t_sha_256_state* state) {
	t_sha_256_digest	digest = {};
	sha_256_word_t		H[8];
	ft_memcpy(H, state->H, sizeof(H));
	size_t		digest_index = 0;
	for (size_t i = 0; i < sizeof(H) / sizeof(sha_256_word_t); ++i) {
		H[i] = PASS_BIG_END(H[i]);
		for (size_t j = 0; j < sizeof(sha_256_word_t); ++j) {
			digest.digest[digest_index] = H[i] % 256;
			H[i] /= 256;
			digest_index += 1;
		}
	}
	return digest;
}
