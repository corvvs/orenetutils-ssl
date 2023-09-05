#include "ft_ssl_md5_internal.h"
#include "ft_ssl_common.h"

static t_md5_state	init_state(const uint8_t *message, uint64_t message_len) {
	return MD5_INITIAL_STATE(message, message_len);
}

static bool	block_operation(t_md5_state* state) {
	DEBUGWARN("BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + MD5_WORD_BLOCK_BIT_SIZE);

	// パディング
	md5_block_padding(state);

	// 演算
	md5_block_rounds(state);

	// ブロックバッファをクリア
	ft_memset(state->X, 0, sizeof(state->X));
	DEBUGWARN("END BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + MD5_WORD_BLOCK_BIT_SIZE);
	state->block_from += MD5_WORD_BLOCK_BIT_SIZE;
	return state->block_from < state->padded_message_len;
}

// ハッシュフロー
define_hash_flow(md5, MD5)

void	digest_md5(const uint8_t* message, size_t bit_len) {
	t_md5_digest digest = md5_hash(message, bit_len);
	for (size_t i = 0; i < sizeof(digest.digest) / sizeof(uint8_t); i++) {
		printf("%02x", digest.digest[i]);
	}
	printf("\n");
}
