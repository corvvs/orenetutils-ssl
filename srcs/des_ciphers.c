#include "ft_ssl_des_internal.h"

// [ブロック暗号本体の定義]

// [DES]
static uint64_t	des_crypt(uint64_t block, const t_des_keys* keys, t_des_direction direction) {
	return des_crypt_block(block, &keys->roundkeys[0], direction);
}

const t_des_cipher	g_des_cipher_des = {
	.name = "des",
	.crypt = des_crypt,
	.key_byte_size = DES_KEY_BYTE_SIZE,
	.key_count = 1,
};

// [Triple DES]
static uint64_t	des3_crypt(uint64_t blck, const t_des_keys* keys, t_des_direction direction) {
	if (direction == DES_DECRYPT) {
		blck = des_crypt_block(blck, &keys->roundkeys[2], DES_DECRYPT);
		blck = des_crypt_block(blck, &keys->roundkeys[1], DES_ENCRYPT);
		return des_crypt_block(blck, &keys->roundkeys[0], DES_DECRYPT);
	} else {
		blck = des_crypt_block(blck, &keys->roundkeys[0], DES_ENCRYPT);
		blck = des_crypt_block(blck, &keys->roundkeys[1], DES_DECRYPT);
		return des_crypt_block(blck, &keys->roundkeys[2], DES_ENCRYPT);
	}
}

const t_des_cipher	g_des_cipher_des3 = {
	.name = "des3",
	.crypt = des3_crypt,
	.key_byte_size = DES3_KEY_BYTE_SIZE,
	.key_count = 3,
};
