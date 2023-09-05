#include "ft_ssl_sha_2_internal.h"

extern int g_is_little_endian;

// mem にビット単位でデータをセットする
// セット範囲: [mem + bit_offset, mem + bit_offset + bit_len)
// セット値: bit
static void	bitwise_memset(uint8_t* mem, const uint8_t bit, uint64_t bit_offset, uint64_t bit_len) {
	DEBUGOUT("bitwise_memset: bit_offset: " U64T ", bit_len: " U64T, bit_offset, bit_len);
	const uint64_t	bit_from = bit_offset;
	const uint64_t	bit_to = bit_offset + bit_len;
	DEBUGOUT("bitwise_memset: bit_from: " U64T ", bit_to: " U64T, bit_from, bit_to);

	// 特殊ケース: コピー範囲が最初の１オクテットに収まっている
	if (bit_to < OCTET_BIT_SIZE) {
		subbyte_memset(mem, bit, bit_from, bit_to);
		return;
	}

	const uint64_t	byte_from = bit_from / OCTET_BIT_SIZE + (bit_from % OCTET_BIT_SIZE > 0 ? 1 : 0);
	const uint64_t	byte_to = bit_to / OCTET_BIT_SIZE;
	if (bit_to < bit_from) {
		DEBUGFATAL("bit_to " U64T " < bit_from " U64T, bit_to, bit_from)
		return;
	}

	// 前のサブバイトコピー
	if (bit_from % OCTET_BIT_SIZE > 0) {
		const uint64_t	byte_index = bit_from / OCTET_BIT_SIZE;
		subbyte_memset(&mem[byte_index], bit, bit_from % OCTET_BIT_SIZE, OCTET_BIT_SIZE);
	}

	// バイトコピー
	if (byte_to > byte_from) {
		DEBUGOUT("memset: [" U64T ", " U64T ")", byte_from, byte_to);
		ft_memset(&mem[byte_from], bit ? 255 : 0, byte_to - byte_from);
	}
	
	// 後のサブバイトコピー
	if (bit_to % OCTET_BIT_SIZE > 0) {
		const uint64_t	byte_index = bit_to / OCTET_BIT_SIZE;
		subbyte_memset(&mem[byte_index], bit, 0, bit_to % OCTET_BIT_SIZE);
	}
}

static bool	do_message_copy(const t_sha_256_state* state) {
	return state->block_from < state->message_len;
}

static void	copy_message_data(t_sha_256_state* state) {
	if (!do_message_copy(state)) { return; }
	const size_t copy_bit_size = FT_MIN(512, state->message_len - state->block_from);
	const size_t copy_byte_size = (copy_bit_size - 1) / OCTET_BIT_SIZE + 1;
	ft_memcpy(state->X, state->message + state->block_from, copy_byte_size);
	DEBUGOUT("COPY MESSAGE DATA from " U64T " to " U64T, state->block_from, state->block_from + copy_bit_size);
}

static bool	do_one_padding(const t_sha_256_state* state) {
	return state->block_from < state->message_1bp_len
		&& state->message_1bp_len <= state->block_from + SHA_2_WORD_BLOCK_BIT_SIZE;
}

static void	one_padding(t_sha_256_state* state) {
	if (!do_one_padding(state)) { return; }
	const uint64_t	padding_bit_pos = state->message_len % SHA_2_WORD_BLOCK_BIT_SIZE;
	const uint64_t	padding_byte_pos = padding_bit_pos / OCTET_BIT_SIZE;
	set_bit_at((uint8_t*)state->X + padding_byte_pos, padding_bit_pos % OCTET_BIT_SIZE, 1);
	DEBUGOUT("ONE PADDING at bit pos: " U64T, padding_bit_pos);
}

static bool	do_zero_padding_former(const t_sha_256_state* state) {
	return state->block_from < state->message_0bp_len
		&& state->message_0bp_len <= state->block_from + SHA_2_WORD_BLOCK_BIT_SIZE;
}

static bool	do_zero_padding_latter(const t_sha_256_state* state) {
	return state->block_from < state->padded_message_len
		&& state->message_1bp_len + 1 <= state->block_from + SHA_2_WORD_BLOCK_BIT_SIZE;
}

static void	zero_padding(t_sha_256_state* state) {
	if (do_zero_padding_former(state)) {
		const uint64_t	set_from = FT_MAX(state->block_from, state->message_1bp_len);
		const uint64_t	set_to = state->message_0bp_len;
		bitwise_memset((uint8_t*)state->X, 0, set_from % SHA_2_WORD_BLOCK_BIT_SIZE, set_to - set_from);
		DEBUGOUT("ZERO PADDING on bit range: [" U64T ", " U64T ")", set_from, set_to);
	} else if (do_zero_padding_latter(state)) {
		const uint64_t	set_from = state->message_1bp_len;
		const uint64_t	set_to = ((state->message_1bp_len - 1) / SHA_2_WORD_BLOCK_BIT_SIZE + 1) * SHA_2_WORD_BLOCK_BIT_SIZE;
		bitwise_memset((uint8_t*)state->X, 0, set_from % SHA_2_WORD_BLOCK_BIT_SIZE, set_to - set_from);
		DEBUGOUT("ZERO PADDING on bit range: [" U64T ", " U64T ")", set_from, set_to);
	}
}

static bool	do_size_padding(const t_sha_256_state* state) {
	return state->block_from + SHA_2_WORD_BLOCK_BIT_SIZE == state->padded_message_len;
}

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
	const uint64_t	size_from = SHA_2_WORD_BLOCK_BIT_SIZE - sizeof(uint64_t) * OCTET_BIT_SIZE;
	uint64_t*	size = (uint64_t *)((uint8_t *)state->X + size_from / OCTET_BIT_SIZE);
	DEBUGOUT("g_is_little_endian: %d", g_is_little_endian);
	*size = PASS_BIG_END(s_64);
	DEBUGOUT("SIZE PADDING: " U64T " into [" U64T ", " U64T ")",
		s_64,
		size_from, size_from + sizeof(uint64_t) * OCTET_BIT_SIZE);
}

static void	print_byte_array(const uint8_t* bytes, size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (0 < i && i % 8 == 0) { printf(" "); }
		if (0 < i && i % 16 == 0) { printf(" "); }
		printf("%02x", bytes[i]);
	}
	printf("\n");
}

void	sha_256_block_padding(t_sha_256_state* state) {
	// 入力データをブロックバッファにコピー
	copy_message_data(state);
	print_byte_array((const uint8_t*)state->X, 512 / 8);
	// 1パディングを行う
	one_padding(state);
	print_byte_array((const uint8_t*)state->X, 512 / 8);
	// 0パディングを行う
	zero_padding(state);
	print_byte_array((const uint8_t*)state->X, 512 / 8);
	// サイズパディングを行う
	size_padding(state);
	print_byte_array((const uint8_t*)state->X, 512 / 8);
}