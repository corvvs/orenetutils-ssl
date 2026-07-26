#include "ft_ssl_des_internal.h"

// [ブロック暗号本体の定義]

// [DES]
static uint64_t	des_crypt(uint64_t block, const t_des_keys* keys, bool decrypt) {
	return des_crypt_block(block, &keys->roundkeys[0], decrypt);
}

const t_des_cipher	g_des_cipher_des = {
	.name = "des",
	.crypt = des_crypt,
	.key_byte_size = DES_KEY_BYTE_SIZE,
	.key_count = 1,
};

// [Triple DES]
// 3 本の鍵で Encrypt-Decrypt-Encrypt を行う.
static uint64_t	des3_crypt(uint64_t block, const t_des_keys* keys, bool decrypt) {
	if (decrypt) {
		block = des_crypt_block(block, &keys->roundkeys[2], true);
		block = des_crypt_block(block, &keys->roundkeys[1], false);
		return des_crypt_block(block, &keys->roundkeys[0], true);
	}
	block = des_crypt_block(block, &keys->roundkeys[0], false);
	block = des_crypt_block(block, &keys->roundkeys[1], true);
	return des_crypt_block(block, &keys->roundkeys[2], false);
}

const t_des_cipher	g_des_cipher_des3 = {
	.name = "des3",
	.crypt = des3_crypt,
	.key_byte_size = DES3_KEY_BYTE_SIZE,
	.key_count = 3,
};
