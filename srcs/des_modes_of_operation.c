#include "ft_ssl.h"
#include "generic_message.h"

// パディングおよびアンパディングはスコープ外
// 与えられるデータのサイズはブロックサイズの倍数である

t_generic_message	des_flow_ecb(
	const t_master_des* master,
	const t_generic_message* flow_input,
	const t_des_round_keys* round_keys,
	uint64_t initialize_vector,
	bool is_encryption,
	t_des_block_proc* des_block_proc
) {
	(void)master;
	// ECB - Electronic Codebook
	// 各ブロックを独立に暗号化 / 復号したものを連結して答えとする.
	(void)initialize_vector;
	assert(flow_input->byte_size % DES_BLOCK_BYTE_LEN == 0);
	const void*	mem = flow_input->message;
	t_generic_message	result = new_generic_message(0);
	t_generic_message	temp = {
		.byte_size = 8,
		.message = NULL,
	};
	// ECB 暗号化 / 復号
	// ECB においては暗号化と復号は同じ形をしている
	(void)is_encryption;

	for (size_t	i = 0; i < flow_input->byte_size; i += DES_BLOCK_BYTE_LEN) {
		uint64_t	block_input = *(uint64_t*)(mem + i);
		if (is_little_endian()) {
			block_input = SWAP_BYTE(block_input);
		}
		uint64_t	block_output = des_block_proc(block_input, round_keys);
		if (is_little_endian()) {
			block_output = SWAP_BYTE(block_output);
		}
		temp.message = (void*)&block_output;
		if (!join_assign_generic_message(&result, &temp)) {
			mark_faild_generic_message(&result);
			return result;
		}
	}
	return result;
}
