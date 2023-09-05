#include "ft_ssl_sha_2_internal.h"

extern int g_is_little_endian;

static bool	block_operation(t_sha_256_state* state) {
	DEBUGWARN("BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + SHA_2_WORD_BLOCK_BIT_SIZE);

	// パディング
	sha_256_block_padding(state);

	// 演算
	sha_256_block_rounds(state);

	// ブロックバッファをクリア
	ft_memset(state->schedule.W, 0, sizeof(state->schedule.W));
	DEBUGWARN("END BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + SHA_2_WORD_BLOCK_BIT_SIZE);
	state->block_from += SHA_2_WORD_BLOCK_BIT_SIZE;
	return state->block_from < state->padded_message_len;
}

t_sha_256_digest	sha_256_hash(const uint8_t* message, uint64_t message_len) {
	// 状態の初期化
	t_sha_256_state		state = SHA_256_INITIAL_STATE(message, message_len);
	ft_memcpy(state.H, SHA_256_H0, sizeof(SHA_256_H0));
	DEBUGOUT("message:            \"%s\"", state.message);
	DEBUGOUT("message_len:        " U64T, state.message_len);
	DEBUGOUT("message_1bp_len:    " U64T, state.message_1bp_len);
	DEBUGOUT("message_0bp_len:    " U64T, state.message_0bp_len);
	DEBUGOUT("padded_message_len: " U64T, state.padded_message_len);

	// バッチ処理
	while (block_operation(&state));

	return sha_256_derive_digest(&state);
}

void	digest_sha_2(const uint8_t* message, size_t bit_len) {
	t_sha_256_digest digest = sha_256_hash(message, bit_len);
	for (size_t i = 0; i < sizeof(digest.digest) / sizeof(uint8_t); i++) {
		printf("%02x", digest.digest[i]);
	}
	printf("\n");
}
