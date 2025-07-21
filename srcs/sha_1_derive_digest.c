#include "ft_ssl_sha_1_internal.h"
#include "ft_ssl_common.h"

extern int g_is_little_endian;

t_sha_1_digest	sha_1_derive_digest(const t_sha_1_state* state) {
	t_sha_1_digest	digest = {};
	sha_1_word_t		H[5];
	ft_memcpy(H, state->H, sizeof(H));
	size_t		digest_index = 0;
	size_t i;
	for (i = 0; digest_index < SHA_1_DIGEST_BIT_SIZE / OCTET_BIT_SIZE; ++i) {
		H[i] = PASS_BIG_END(H[i]);
		for (
			size_t j = 0;
			j < sizeof(sha_1_word_t) && digest_index < SHA_1_DIGEST_BIT_SIZE / OCTET_BIT_SIZE;
			++j, ++digest_index
		) {
			digest.digest[digest_index] = H[i] & ((1u << OCTET_BIT_SIZE) - 1);
			H[i] >>= OCTET_BIT_SIZE;
		}
	}
	return digest;
}
