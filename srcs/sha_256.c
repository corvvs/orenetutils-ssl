#include "ft_ssl_sha_2_internal.h"
#include "ft_ssl_common.h"

extern int g_is_little_endian;

static t_sha_256_state	init_state(const uint8_t *message, uint64_t message_len) {
	t_sha_256_state state = SHA_256_INITIAL_STATE(message, message_len);
	ft_memcpy(state.H, SHA_256_H0, sizeof(SHA_256_H0));
	return state;
}

static bool	block_operation(t_sha_256_state* state) {
	DEBUGWARN("BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + SHA_256_WORD_BLOCK_BIT_SIZE);

	// パディング
	sha_256_block_padding(state);

	// 演算
	sha_256_block_rounds(state);

	// ブロックバッファをクリア
	ft_memset(state->schedule.W, 0, sizeof(state->schedule.W));
	DEBUGWARN("END BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + SHA_256_WORD_BLOCK_BIT_SIZE);
	state->block_from += SHA_256_WORD_BLOCK_BIT_SIZE;
	return state->block_from < state->padded_message_len;
}

// ハッシュフロー
define_hash_flow(sha_256, SHA_256)

void	digest_sha_2(const uint8_t* message, size_t bit_len) {
	t_sha_256_digest digest = sha_256_hash(message, bit_len);
	for (size_t i = 0; i < sizeof(digest.digest) / sizeof(uint8_t); i++) {
		printf("%02x", digest.digest[i]);
	}
	printf("\n");
}
