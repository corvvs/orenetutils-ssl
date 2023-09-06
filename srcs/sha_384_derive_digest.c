#include "ft_ssl_sha_2_internal.h"

extern int g_is_little_endian;

t_sha_384_digest	sha_384_derive_digest(const t_sha_384_state* state) {
	t_sha_384_digest	digest = {};
	sha_384_word_t		H[8];
	ft_memcpy(H, state->H, sizeof(H));
	size_t		digest_index = 0;
	for (size_t i = 0; i < SHA_384_DIGEST_BIT_SIZE / (sizeof(sha_384_word_t) * OCTET_BIT_SIZE); ++i) {
		H[i] = PASS_BIG_END(H[i]);
		for (size_t j = 0; j < sizeof(sha_384_word_t); ++j, ++digest_index) {
			digest.digest[digest_index] = H[i] & ((1u << OCTET_BIT_SIZE) - 1);
			H[i] >>= OCTET_BIT_SIZE;
		}
	}
	return digest;
}