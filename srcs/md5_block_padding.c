#include "ft_ssl_md5_internal.h"
#include "ft_ssl_common.h"

extern int g_is_little_endian;

define_block_padding_functions(md5, MD5, X)

typedef union u_bit_size {
	struct {
		uint32_t	little;
		uint32_t	big;
	}			s_32;
	uint64_t	s_64;
}	t_bit_size;

static void 	size_padding(t_md5_state* state) {
	if (!do_size_padding(state)) { return; }
	t_bit_size	bs;
	bs.s_64 = state->message_len;
	const uint64_t	size_from = MD5_WORD_BLOCK_BIT_SIZE - sizeof(uint64_t) * OCTET_BIT_SIZE;
	uint32_t*	little = (uint32_t *)((uint8_t *)state->X + size_from / OCTET_BIT_SIZE);
	uint32_t*	big = little + 1;
	*little = PASS_LIT_END(bs.s_32.little);
	*big = PASS_LIT_END(bs.s_32.big);
	DEBUGOUT("SIZE PADDING: " U64T " (%08x, %08x) into [" U64T ", " U64T ")",
		bs.s_64,
		bs.s_32.little, bs.s_32.big,
		size_from, size_from + sizeof(uint64_t) * OCTET_BIT_SIZE);
}

void	md5_block_padding(t_md5_state* state) {
	// 入力データをブロックバッファにコピー
	copy_message_data(state);
	// 1パディングを行う
	one_padding(state);
	// 0パディングを行う
	zero_padding(state);
	// サイズパディングを行う
	size_padding(state);
}
