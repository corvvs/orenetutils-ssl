#include "ft_ssl_sha_2_internal.h"
#include "ft_ssl_common.h"

extern int g_is_little_endian;

declare_block_padding_functions(sha_224, SHA_224, schedule.X)

static void 	size_padding(t_sha_224_state* state) {
	if (!do_size_padding(state)) { return; }
	const uint64_t s_64 = state->message_len;
	const uint64_t	size_from = SHA_224_WORD_BLOCK_BIT_SIZE - sizeof(uint64_t) * OCTET_BIT_SIZE;
	uint64_t*	size = (uint64_t *)((uint8_t *)state->schedule.X + size_from / OCTET_BIT_SIZE);
	DEBUGOUT("g_is_little_endian: %d", g_is_little_endian);
	*size = PASS_BIG_END(s_64);
	DEBUGOUT("SIZE PADDING: " U64T " into [" U64T ", " U64T ")",
		s_64,
		size_from, size_from + sizeof(uint64_t) * OCTET_BIT_SIZE);
}

void	sha_224_block_padding(t_sha_224_state* state) {
	// 入力データをブロックバッファにコピー
	copy_message_data(state);
	// 1パディングを行う
	one_padding(state);
	// 0パディングを行う
	zero_padding(state);
	// サイズパディングを行う
	size_padding(state);
}
