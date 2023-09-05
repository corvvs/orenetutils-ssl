#include "ft_ssl_sha_2_internal.h"
#include "ft_ssl_common.h"

extern int g_is_little_endian;

define_block_padding_functions(sha_256, SHA_256, schedule.X)

typedef union u_bit_size {
	struct {
		uint32_t	little;
		uint32_t	big;
	}			s_32;
	uint64_t	s_64;
}	t_bit_size;

static void 	size_padding(t_sha_256_state* state) {
	if (!do_size_padding(state)) { return; }
	const uint64_t s_64 = state->message_len;
	const uint64_t	size_from = SHA_256_WORD_BLOCK_BIT_SIZE - sizeof(uint64_t) * OCTET_BIT_SIZE;
	uint64_t*	size = (uint64_t *)((uint8_t *)state->schedule.X + size_from / OCTET_BIT_SIZE);
	DEBUGOUT("g_is_little_endian: %d", g_is_little_endian);
	*size = PASS_BIG_END(s_64);
	DEBUGOUT("SIZE PADDING: " U64T " into [" U64T ", " U64T ")",
		s_64,
		size_from, size_from + sizeof(uint64_t) * OCTET_BIT_SIZE);
}

static void	print_byte_array(const uint8_t* bytes, size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (0 < i && i % 8 == 0) { dprintf(2, " "); }
		if (0 < i && i % 16 == 0) { dprintf(2, " "); }
		dprintf(2, "%02x", bytes[i]);
	}
	dprintf(2, "\n");
}

void	sha_256_block_padding(t_sha_256_state* state) {
	// 入力データをブロックバッファにコピー
	copy_message_data(state);
	print_byte_array((const uint8_t*)state->schedule.X, sizeof(state->schedule.X));
	// 1パディングを行う
	one_padding(state);
	print_byte_array((const uint8_t*)state->schedule.X, sizeof(state->schedule.X));
	// 0パディングを行う
	zero_padding(state);
	print_byte_array((const uint8_t*)state->schedule.X, sizeof(state->schedule.X));
	// サイズパディングを行う
	size_padding(state);
	print_byte_array((const uint8_t*)state->schedule.X, sizeof(state->schedule.X));
}
