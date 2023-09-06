#include "ft_ssl_sha_2_internal.h"
#include "ft_ssl_common.h"
#include "ft_ssl_structure.h"
#include "ft_ssl.h"

extern int g_is_little_endian;

static t_sha_512_state	init_state(const uint8_t *message, uint64_t message_len) {
	t_sha_512_state state = SHA_2_INITIAL_STATE(512, message, message_len);
	ft_memcpy(state.H, SHA_512_H0, sizeof(SHA_512_H0));
	return state;
}

static bool	block_operation(t_sha_512_state* state) {
	DEBUGWARN("BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + SHA_512_WORD_BLOCK_BIT_SIZE);

	// パディング
	sha_512_block_padding(state);

	// 演算
	sha_512_block_rounds(state);

	// ブロックバッファをクリア
	ft_memset(state->schedule.W, 0, sizeof(state->schedule.W));
	DEBUGWARN("END BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + SHA_512_WORD_BLOCK_BIT_SIZE);
	state->block_from += SHA_512_WORD_BLOCK_BIT_SIZE;
	return state->block_from < state->padded_message_len;
}

// ハッシュフロー
define_hash_flow(sha_512, SHA_512)

static void print_digest(const t_sha_512_digest* digest) {
	for (size_t i = 0; i < sizeof(digest->digest) / sizeof(uint8_t); i++) {
		printf("%02x", digest->digest[i]);
	}
}

define_print_digest_line(sha_512, "SHA2-512")

void	digest_sha_512(const t_preference* pref, const t_message* message) {
	t_sha_512_digest digest = sha_512_hash(message->message, message->message_bit_len);
	print_digest_line(pref, message, &digest);
}
