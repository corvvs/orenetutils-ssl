#include "ft_ssl_des_internal.h"

// [ブロック連鎖モードの定義]
// どのモードも暗号本体 (ctx->cipher) を呼ぶだけで, 違いは
// 「ブロックをどう連鎖させるか」に閉じている.
// 本体が DES か Triple DES かはここでは関知しない.
//
//   ECB: C_i = E(P_i)
//        P_i = D(C_i)
//   CBC: C_i = E(P_i ^ C_{i-1})
//        P_i = D(C_i) ^ C_{i-1} (C_0 = IV)

// [ECB]
static uint64_t	ecb_encrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	(void)chain;
	return ctx->cipher->crypt(block, ctx->keys, false);
}

static uint64_t	ecb_decrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	(void)chain;
	return ctx->cipher->crypt(block, ctx->keys, true);
}

const t_des_mode	g_des_mode_ecb = {
	.name = "ecb",
	.encrypt = ecb_encrypt,
	.decrypt = ecb_decrypt,
	.uses_iv = false,
	.uses_padding = true,
};

// [CBC]
// 暗号化・復号のどちらでも, 次の連鎖値になるのは暗号文側であることに注意.

static uint64_t	cbc_encrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	const uint64_t	encrypted = ctx->cipher->crypt(block ^ *chain, ctx->keys, false);
	// 出力ブロック(暗号文)が次の連鎖値になる
	*chain = encrypted;
	return encrypted;
}

static uint64_t	cbc_decrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	const uint64_t	decrypted = ctx->cipher->crypt(block, ctx->keys, true) ^ *chain;
	// 入力ブロック(暗号文)がそのまま次の連鎖値になる
	*chain = block;
	return decrypted;
}

const t_des_mode	g_des_mode_cbc = {
	.name = "cbc",
	.encrypt = cbc_encrypt,
	.decrypt = cbc_decrypt,
	.uses_iv = true,
	.uses_padding = true,
};

// [OFB]
// 鍵ストリーム O_i = E(O_{i-1}) を作り, データと XOR するだけ (O_0 = IV).
// 連鎖値は暗号文ではなく鍵ストリームそのもので, データには依存しない.
// そのため暗号化と復号がまったく同じ処理になり, 復号でも暗号化方向の変換を使う.
static uint64_t	ofb_crypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	*chain = ctx->cipher->crypt(*chain, ctx->keys, false);
	return block ^ *chain;
}

const t_des_mode	g_des_mode_ofb = {
	.name = "ofb",
	.encrypt = ofb_crypt,
	.decrypt = ofb_crypt,
	.uses_iv = true,
	.uses_padding = false,
};
