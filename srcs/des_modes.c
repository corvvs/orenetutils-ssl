#include "ft_ssl_des_internal.h"

// [ブロック連鎖モードの定義]
// どのモードも des_crypt_block() (コア) を呼ぶだけで, 違いは
// 「ブロックをどう連鎖させるか」に閉じている.
//
//   ECB: C_i = E(P_i)
//        P_i = D(C_i)
//   CBC: C_i = E(P_i ^ C_{i-1})
//        P_i = D(C_i) ^ C_{i-1} (C_0 = IV)

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

// [CBC]
// 暗号化・復号のどちらでも, 次の連鎖値になるのは暗号文側であることに注意.

static uint64_t	cbc_encrypt(uint64_t block, const t_des_roundkeys* roundkeys, uint64_t* chain) {
	const uint64_t	encrypted = des_crypt_block(block ^ *chain, roundkeys, false);
	// 出力ブロック(暗号文)が次の連鎖値になる
	*chain = encrypted;
	return encrypted;
}

static uint64_t	cbc_decrypt(uint64_t block, const t_des_roundkeys* roundkeys, uint64_t* chain) {
	const uint64_t	decrypted = des_crypt_block(block, roundkeys, true) ^ *chain;
	// 入力ブロック(暗号文)がそのまま次の連鎖値になる
	*chain = block;
	return decrypted;
}

const t_des_mode	g_des_mode_cbc = {
	.name = "des-cbc",
	.encrypt = cbc_encrypt,
	.decrypt = cbc_decrypt,
	.uses_iv = true,
};
