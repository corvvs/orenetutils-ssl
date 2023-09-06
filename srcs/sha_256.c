#include "ft_ssl_sha_2_internal.h"
#include "ft_ssl_common.h"
#include "ft_ssl_structure.h"
#include "ft_ssl.h"

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
declare_hash_flow(sha_256, SHA_256)

static void print_digest(const t_sha_256_digest* digest) {
	for (size_t i = 0; i < sizeof(digest->digest) / sizeof(uint8_t); i++) {
		printf("%02x", digest->digest[i]);
	}
}

declare_print_digest_line(sha_256, "SHA2-256")

void	digest_sha_256(const t_preference* pref, const t_message* message) {
	t_sha_256_digest digest = sha_256_hash(message->message, message->message_bit_len);
	print_digest_line(pref, message, &digest);
}
