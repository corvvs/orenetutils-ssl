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
	return ctx->cipher->crypt(block, ctx->keys, DES_ENCRYPT);
}

static uint64_t	ecb_decrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	(void)chain;
	return ctx->cipher->crypt(block, ctx->keys, DES_DECRYPT);
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
	const uint64_t	encrypted = ctx->cipher->crypt(block ^ *chain, ctx->keys, DES_ENCRYPT);
	// 出力ブロック(暗号文)が次の連鎖値になる
	*chain = encrypted;
	return encrypted;
}

static uint64_t	cbc_decrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	const uint64_t	decrypted = ctx->cipher->crypt(block, ctx->keys, DES_DECRYPT) ^ *chain;
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
	*chain = ctx->cipher->crypt(*chain, ctx->keys, DES_ENCRYPT);
	return block ^ *chain;
}

const t_des_mode	g_des_mode_ofb = {
	.name = "ofb",
	.encrypt = ofb_crypt,
	.decrypt = ofb_crypt,
	.uses_iv = true,
	.uses_padding = false,
};

// [CFB]
// 直前の暗号文ブロックを暗号化して鍵ストリームを作り, データと XOR する (C_0 = IV).
// OFB と同じく, 復号でも暗号化方向の変換しか使わない.
// 連鎖値は CBC と同じく暗号文なので, 暗号化では出力を, 復号では入力を次に渡す.
static uint64_t	cfb_encrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	const uint64_t	encrypted = block ^ ctx->cipher->crypt(*chain, ctx->keys, DES_ENCRYPT);
	*chain = encrypted;
	return encrypted;
}

static uint64_t	cfb_decrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	const uint64_t	decrypted = block ^ ctx->cipher->crypt(*chain, ctx->keys, DES_ENCRYPT);
	// 入力ブロック(暗号文)がそのまま次の連鎖値になる
	*chain = block;
	return decrypted;
}

const t_des_mode	g_des_mode_cfb = {
	.name = "cfb",
	.encrypt = cfb_encrypt,
	.decrypt = cfb_decrypt,
	.uses_iv = true,
	.uses_padding = false,
};

// [CTR]
// カウンタブロックを暗号化して鍵ストリームを作り, データと XOR する.
//   C_i = P_i ^ E(counter + i)   (counter の初期値は IV)
// 鍵ストリームがデータに依存しない点は OFB と同じで, 暗号化と復号は同じ処理になる.
// OFB との違いは, 次の鍵ストリームを「前の鍵ストリームの暗号化」ではなく
// 「カウンタを進めて暗号化」で作ること.
static uint64_t	ctr_crypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	const uint64_t	keystream = ctx->cipher->crypt(*chain, ctx->keys, DES_ENCRYPT);
	*chain += 1; // 規格としては正でありさえすればいいが, 互換性/相互運用性を考えると +1 するしかない
	return block ^ keystream;
}

const t_des_mode	g_des_mode_ctr = {
	.name = "ctr",
	.encrypt = ctr_crypt,
	.decrypt = ctr_crypt,
	.uses_iv = true,
	.uses_padding = false,
};

// [PCBC]
// CBC の連鎖値を「直前の暗号文」から「直前の平文と暗号文の XOR」に変えたもの.
//   C_i = E(P_i ^ P_{i-1} ^ C_{i-1})   /   P_i = D(C_i) ^ P_{i-1} ^ C_{i-1}
//   (P_0 ^ C_0 = IV)
// CBC と違い誤りが後続ブロックすべてに伝播する (Propagating CBC).
// 連鎖値に平文と暗号文の両方が要るが, どちらも 1 ブロック分の処理の中で
// 手に入る (入力と出力) ので, 追加の状態は要らない.
static uint64_t	pcbc_encrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	const uint64_t	encrypted = ctx->cipher->crypt(block ^ *chain, ctx->keys, DES_ENCRYPT);
	// 平文 ^ 暗号文 が次の連鎖値になる
	*chain = block ^ encrypted;
	return encrypted;
}

static uint64_t	pcbc_decrypt(uint64_t block, const t_des_block_context* ctx, uint64_t* chain) {
	const uint64_t	decrypted = ctx->cipher->crypt(block, ctx->keys, DES_DECRYPT) ^ *chain;
	// 復号側でも同じく 平文 ^ 暗号文 (ここでは 出力 ^ 入力)
	*chain = decrypted ^ block;
	return decrypted;
}

const t_des_mode	g_des_mode_pcbc = {
	.name = "pcbc",
	.encrypt = pcbc_encrypt,
	.decrypt = pcbc_decrypt,
	.uses_iv = true,
	.uses_padding = true,
};
