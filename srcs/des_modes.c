#include "ft_ssl_des_internal.h"

// [ブロック連鎖モードの定義]
// どのモードも des_crypt_block() (コア) を呼ぶだけで, 違いは
// 「ブロックをどう連鎖させるか」に閉じている.
//
//   ECB: C_i = E(P_i)              / P_i = D(C_i)

// [ECB]
static uint64_t	ecb_encrypt(uint64_t block, const t_des_roundkeys* roundkeys, uint64_t* chain) {
	(void)chain;
	return des_crypt_block(block, roundkeys, false);
}

static uint64_t	ecb_decrypt(uint64_t block, const t_des_roundkeys* roundkeys, uint64_t* chain) {
	(void)chain;
	return des_crypt_block(block, roundkeys, true);
}

const t_des_mode	g_des_mode_ecb = {
	.name = "des-ecb",
	.encrypt = ecb_encrypt,
	.decrypt = ecb_decrypt,
	.uses_iv = false,
};
