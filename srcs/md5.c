#include "ft_ssl_md5_internal.h"

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

t_md5_digest	md5_hash(const uint8_t* message, uint64_t message_len) {
	// 状態の初期化
	t_md5_state		state = MD5_INITIAL_STATE(message, message_len);
	DEBUGOUT("message:            \"%s\"", state.message);
	DEBUGOUT("message_len:        " U64T, state.message_len);
	DEBUGOUT("message_1bp_len:    " U64T, state.message_1bp_len);
	DEBUGOUT("message_0bp_len:    " U64T, state.message_0bp_len);
	DEBUGOUT("padded_message_len: " U64T, state.padded_message_len);

	// バッチ処理
	while (block_operation(&state));

	return md5_derive_digest(&state);
}

void	digest_md5(const uint8_t* message, size_t bit_len) {
	t_md5_digest digest = md5_hash(message, bit_len);
	for (size_t i = 0; i < sizeof(digest.digest) / sizeof(uint8_t); i++) {
		printf("%02x", digest.digest[i]);
	}
	printf("\n");
}
