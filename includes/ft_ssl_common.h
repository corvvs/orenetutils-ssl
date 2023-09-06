#ifndef FT_SSL_COMMON_H
#define FT_SSL_COMMON_H

// ハッシュごとのフロー関数を定義する.
// declare_hash_flow(md5, MD5)
// declare_hash_flow(sha_256, SHA_256)
#define declare_hash_flow(hash_type, HASH_TYPE)                                            \
	t_##hash_type##_digest hash_type##_hash(const uint8_t *message, uint64_t message_len) \
	{                                                                                     \
		t_##hash_type##_state state = init_state(message, message_len);                   \
		DEBUGOUT("message_len:        " U64T, state.message_len);                         \
		DEBUGOUT("message_1bp_len:    " U64T, state.message_1bp_len);                     \
		DEBUGOUT("message_0bp_len:    " U64T, state.message_0bp_len);                     \
		DEBUGOUT("padded_message_len: " U64T, state.padded_message_len);                  \
                                                                                          \
		while (block_operation(&state))                                                   \
			;                                                                             \
                                                                                          \
		return hash_type##_derive_digest(&state);                                         \
	}

#define declare_block_padding_functions(hash_type, HASH_TYPE, BLOCK_BUFFER)                                            \
	static void bitwise_memset(uint8_t *mem, const uint8_t bit, uint64_t bit_offset, uint64_t bit_len)                \
	{                                                                                                                 \
		const uint64_t bit_from = bit_offset;                                                                         \
		const uint64_t bit_to = bit_offset + bit_len;                                                                 \
		DEBUGOUT("bitwise_memset: bit_from: " U64T ", bit_to: " U64T, bit_from, bit_to);                              \
                                                                                                                      \
		/* 特殊ケース: コピー範囲が最初の１オクテットに収まっている */                     \
		if (bit_to < OCTET_BIT_SIZE)                                                                                  \
		{                                                                                                             \
			subbyte_memset(mem, bit, bit_from, bit_to);                                                               \
			return;                                                                                                   \
		}                                                                                                             \
                                                                                                                      \
		const uint64_t byte_from = bit_from / OCTET_BIT_SIZE + (bit_from % OCTET_BIT_SIZE > 0 ? 1 : 0);               \
		const uint64_t byte_to = bit_to / OCTET_BIT_SIZE;                                                             \
		if (bit_to < bit_from)                                                                                        \
		{                                                                                                             \
			DEBUGFATAL("bit_to " U64T " < bit_from " U64T, bit_to, bit_from);                                         \
			return;                                                                                                   \
		}                                                                                                             \
                                                                                                                      \
		/* 前のサブバイトコピー */                                                                          \
		if (bit_from % OCTET_BIT_SIZE > 0)                                                                            \
		{                                                                                                             \
			const uint64_t byte_index = bit_from / OCTET_BIT_SIZE;                                                    \
			subbyte_memset(&mem[byte_index], bit, bit_from % OCTET_BIT_SIZE, OCTET_BIT_SIZE);                         \
		}                                                                                                             \
                                                                                                                      \
		/* バイトコピー */                                                                                      \
		if (byte_to > byte_from)                                                                                      \
		{                                                                                                             \
			DEBUGOUT("memset: [" U64T ", " U64T ")", byte_from, byte_to);                                             \
			ft_memset(&mem[byte_from], bit ? 255 : 0, byte_to - byte_from);                                           \
		}                                                                                                             \
                                                                                                                      \
		/* 後のサブバイトコピー */                                                                          \
		if (bit_to % OCTET_BIT_SIZE > 0)                                                                              \
		{                                                                                                             \
			const uint64_t byte_index = bit_to / OCTET_BIT_SIZE;                                                      \
			subbyte_memset(&mem[byte_index], bit, 0, bit_to % OCTET_BIT_SIZE);                                        \
		}                                                                                                             \
	}                                                                                                                 \
                                                                                                                      \
	static bool do_message_copy(const t_##hash_type##_state *state)                                                   \
	{                                                                                                                 \
		return state->block_from < state->message_len;                                                                \
	}                                                                                                                 \
                                                                                                                      \
	static void copy_message_data(t_##hash_type##_state *state)                                                       \
	{                                                                                                                 \
		if (!do_message_copy(state))                                                                                  \
		{                                                                                                             \
			return;                                                                                                   \
		}                                                                                                             \
		const size_t copy_bit_size = FT_MIN(HASH_TYPE##_WORD_BLOCK_BIT_SIZE, state->message_len - state->block_from); \
		const uint64_t copy_bit_from = state->block_from;                                                             \
		const uint64_t copy_bit_to = state->block_from + copy_bit_size;                                               \
		const uint64_t copy_byte_from = copy_bit_from / OCTET_BIT_SIZE;                                               \
		const uint64_t copy_byte_to = (copy_bit_to - 1) / OCTET_BIT_SIZE + 1;                                         \
		ft_memcpy(state->BLOCK_BUFFER, state->message + copy_byte_from, copy_byte_to - copy_byte_from);               \
	}                                                                                                                 \
                                                                                                                      \
	static bool do_one_padding(const t_##hash_type##_state *state)                                                    \
	{                                                                                                                 \
		const uint64_t from = state->block_from;                                                                      \
		const uint64_t to = state->block_from + HASH_TYPE##_WORD_BLOCK_BIT_SIZE;                                      \
		return from < state->message_1bp_len && state->message_1bp_len <= to;                                         \
	}                                                                                                                 \
	static void one_padding(t_##hash_type##_state *state)                                                             \
	{                                                                                                                 \
		if (!do_one_padding(state))                                                                                   \
		{                                                                                                             \
			return;                                                                                                   \
		}                                                                                                             \
		const uint64_t padding_bit_pos = state->message_len % HASH_TYPE##_WORD_BLOCK_BIT_SIZE;                        \
		const uint64_t padding_byte_pos = padding_bit_pos / OCTET_BIT_SIZE;                                           \
		set_bit_at((uint8_t *)state->BLOCK_BUFFER + padding_byte_pos, padding_bit_pos % OCTET_BIT_SIZE, 1);           \
		DEBUGOUT("ONE PADDING at bit pos: " U64T, padding_bit_pos);                                                   \
	}                                                                                                                 \
	static bool do_zero_padding_former(const t_##hash_type##_state *state)                                            \
	{                                                                                                                 \
		const uint64_t from = state->block_from;                                                                      \
		const uint64_t to = state->block_from + HASH_TYPE##_WORD_BLOCK_BIT_SIZE;                                      \
		return from < state->message_0bp_len && state->message_0bp_len <= to;                                         \
	}                                                                                                                 \
                                                                                                                      \
	static bool do_zero_padding_latter(const t_##hash_type##_state *state)                                            \
	{                                                                                                                 \
		const uint64_t from = state->block_from;                                                                      \
		const uint64_t to = state->block_from + HASH_TYPE##_WORD_BLOCK_BIT_SIZE;                                      \
		return from < state->padded_message_len && state->message_1bp_len + 1 <= to;                                  \
	}                                                                                                                 \
                                                                                                                      \
	static void zero_padding(t_##hash_type##_state *state)                                                            \
	{                                                                                                                 \
		if (do_zero_padding_former(state))                                                                            \
		{                                                                                                             \
			const uint64_t set_from = FT_MAX(state->block_from, state->message_1bp_len);                              \
			const uint64_t block_bit_size = HASH_TYPE##_WORD_BLOCK_BIT_SIZE;                                          \
			const uint64_t set_to = state->message_0bp_len;                                                           \
			bitwise_memset((uint8_t *)state->BLOCK_BUFFER, 0, set_from % block_bit_size, set_to - set_from);          \
			DEBUGOUT("ZERO PADDING on bit range: [" U64T ", " U64T ")", set_from, set_to);                            \
		}                                                                                                             \
		else if (do_zero_padding_latter(state))                                                                       \
		{                                                                                                             \
			const uint64_t set_from = state->message_1bp_len;                                                         \
			const uint64_t block_bit_size = HASH_TYPE##_WORD_BLOCK_BIT_SIZE;                                          \
			const uint64_t set_to = ((state->message_1bp_len - 1) / block_bit_size + 1) * block_bit_size;             \
			bitwise_memset((uint8_t *)state->BLOCK_BUFFER, 0, set_from % block_bit_size, set_to - set_from);          \
			DEBUGOUT("ZERO PADDING on bit range: [" U64T ", " U64T ")", set_from, set_to);                            \
		}                                                                                                             \
	}                                                                                                                 \
                                                                                                                      \
	static bool do_size_padding(const t_##hash_type##_state *state)                                                   \
	{                                                                                                                 \
		return state->block_from + HASH_TYPE##_WORD_BLOCK_BIT_SIZE == state->padded_message_len;                      \
	}

#define declare_print_digest_line(hash_type, hash_prefix)                                                                   \
	static void print_digest_line(const t_preference *pref, const t_message *message, const t_##hash_type##_digest *digest) \
	{                                                                                                                       \
		const bool current_is_stdin = message->is_bytestream && message->file_path == NULL;                                 \
		if (pref->is_quiet)                                                                                                 \
		{                                                                                                                   \
			if (pref->is_echo && current_is_stdin)                                                                          \
			{                                                                                                               \
				put_bytestream(STDOUT_FILENO,                                                                               \
							   message->message,                                                                            \
							   message->message_bit_len > 0                                                                 \
								   ? (message->message_bit_len - 1) / OCTET_BIT_SIZE + 1                                    \
								   : 0);                                                                                    \
				printf("\n");                                                                                               \
			}                                                                                                               \
			print_digest(digest);                                                                                           \
		}                                                                                                                   \
		else if (pref->is_reverse && !current_is_stdin)                                                                                          \
		{                                                                                                                   \
			print_digest(digest);                                                                                           \
			printf(" ");                                                                                                    \
			if (message->is_bytestream)                                                                                     \
			{                                                                                                               \
				printf("%s", message->file_path ? message->file_path : "-");                                                \
			}                                                                                                               \
			else                                                                                                            \
			{                                                                                                               \
				printf("\"%s\"", message->message);                                                                         \
			}                                                                                                               \
		}                                                                                                                   \
		else                                                                                                                \
		{                                                                                                                   \
			if (current_is_stdin)                                                                                           \
			{                                                                                                               \
				if (pref->is_echo)                                                                                          \
				{                                                                                                           \
					ft_putstr_fd("(\"", STDOUT_FILENO);                                                                                          \
					put_bytestream(STDOUT_FILENO,                                                                           \
								   message->message,                                                                        \
								   message->message_bit_len > 0                                                             \
									   ? (message->message_bit_len - 1) / OCTET_BIT_SIZE + 1                                \
									   : 0);                                                                                \
					ft_putstr_fd("\")= ", STDOUT_FILENO);                                                                                        \
				}                                                                                                           \
				else                                                                                                        \
				{                                                                                                           \
					ft_putstr_fd("(stdin)= ", STDOUT_FILENO);                                                                                    \
				}                                                                                                           \
			}                                                                                                               \
			else if (message->is_bytestream)                                                                                \
			{                                                                                                               \
				printf(hash_prefix " (%s) = ", message->file_path);                                                         \
			}                                                                                                               \
			else                                                                                                            \
			{                                                                                                               \
				printf(hash_prefix " (\"%s\") = ", message->message);                                                       \
			}                                                                                                               \
			print_digest(digest);                                                                                           \
		}                                                                                                                   \
		printf("\n");                                                                                                       \
	}

#define declare_sha2_derive_digest(hash_type, HASH_TYPE) \
t_##hash_type##_digest	hash_type##_derive_digest(const t_##hash_type##_state* state) {\
	t_##hash_type##_digest	digest = {};\
	hash_type##_word_t		H[8];\
	ft_memcpy(H, state->H, sizeof(H));\
	size_t		digest_index = 0;\
	size_t i;\
	for (i = 0; digest_index < HASH_TYPE##_DIGEST_BIT_SIZE / OCTET_BIT_SIZE; ++i) {\
		H[i] = PASS_BIG_END(H[i]);\
		for (\
			size_t j = 0;\
			j < sizeof(hash_type##_word_t) && digest_index < HASH_TYPE##_DIGEST_BIT_SIZE / OCTET_BIT_SIZE;\
			++j, ++digest_index\
		) {\
			digest.digest[digest_index] = H[i] & ((1u << OCTET_BIT_SIZE) - 1);\
			H[i] >>= OCTET_BIT_SIZE;\
		}\
	}\
	return digest;\
}

#endif
