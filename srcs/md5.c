#include "ft_ssl_md5_internal.h"

extern int g_is_little_endian;

static void	print_states(unsigned int abcd[4]) {
	printf("%08x %08x %08x %08x\n", abcd[0], abcd[1], abcd[2], abcd[3]);
}

static bool	block_operation(t_md5_state* state) {
	DEBUGWARN("BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + MD5_WORD_BLOCK_BIT_SIZE);

	// パディング
	md5_block_padding(state);

	md5_word_t	ABCD[] = { state->A, state->B, state->C, state->D };
	print_states((unsigned int[]){ state->A, state->B, state->C, state->D });

	// 演算
	md5_block_rounds(state);

	// ワードバッファ更新
	state->A += ABCD[0];
	state->B += ABCD[1];
	state->C += ABCD[2];
	state->D += ABCD[3];

	print_states((unsigned int[]){ state->A, state->B, state->C, state->D });

	// ブロックバッファをクリア
	ft_memset(state->X, 0, sizeof(state->X));
	DEBUGWARN("END BLOCK OPERATION for [" U64T ", " U64T ")", state->block_from, state->block_from + MD5_WORD_BLOCK_BIT_SIZE);
	state->block_from += MD5_WORD_BLOCK_BIT_SIZE;
	return state->block_from < state->padded_message_len;
}

static t_md5_digest	derive_digest(const t_md5_state* state) {
	t_md5_digest	digest = {};
	md5_word_t	ABCD[] = { state->A, state->B, state->C, state->D };
	size_t		digest_index = 0;
	for (size_t i = 0; i < sizeof(ABCD) / sizeof(md5_word_t); ++i) {
		ABCD[i] = PASS_LIT_END(ABCD[i]);
		for (size_t j = 0; j < sizeof(md5_word_t); ++j) {
			digest.digest[digest_index] = ABCD[i] % 256;
			ABCD[i] /= 256;
			digest_index += 1;
		}
	}
	return digest;
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

	return derive_digest(&state);
}

void	digest_md5(const uint8_t* message, size_t bit_len) {
	t_md5_digest digest = md5_hash(message, bit_len);
	printf("digest:\n");
	for (size_t i = 0; i < sizeof(digest.digest) / sizeof(uint8_t); i++) {
		printf("%02x", digest.digest[i]);
	}
	printf("\n");
}
