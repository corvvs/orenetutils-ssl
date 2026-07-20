#include "ft_ssl_des_internal.h"

// [DES ブロック暗号のコア]
// FIPS 46-3 の各テーブルを 1-indexed (MSB=1) のまま持ち, permute() で駆動する.
// バリアント (ECB/CBC/3DES/...) はこの des_crypt_block() を組み合わせるだけで表現し,
// コアの置換・Feistel ロジックはここ 1 箇所に集約する.

// 初期転置 IP (64 -> 64)
static const uint8_t	DES_IP[64] = {
	58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
	57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
};

// 最終転置 FP = IP^-1 (64 -> 64)
static const uint8_t	DES_FP[64] = {
	40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25,
};

// 拡大置換 E (32 -> 48)
static const uint8_t	DES_E[48] = {
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1,
};

// 転置 P (32 -> 32)
static const uint8_t	DES_P[32] = {
	16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
	 2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25,
};

// 鍵転置 PC-1 (64 -> 56)
static const uint8_t	DES_PC1[56] = {
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
};

// 鍵転置 PC-2 (56 -> 48)
static const uint8_t	DES_PC2[48] = {
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
};

// 各ラウンドの左巡回シフト量
static const uint8_t	DES_SHIFT[DES_ROUNDS] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

// S ボックス S1 .. S8 (それぞれ 4 行 16 列)
static const uint8_t	DES_S[8][4][16] = {
	{
		{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
		{ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
		{ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
		{15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
	},
	{
		{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
		{ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
		{ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
		{13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
	},
	{
		{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
		{13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
		{13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
		{ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
	},
	{
		{ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
		{13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
		{10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
		{ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
	},
	{
		{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
		{14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
		{ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
		{11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
	},
	{
		{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
		{10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
		{ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
		{ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
	},
	{
		{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
		{13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
		{ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
		{ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
	},
	{
		{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
		{ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
		{ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
		{ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
	},
};

// src の下位 in_bits ビットに対しテーブル (1-indexed, MSB=1) で転置を行い,
// out_bits ビットの結果を返す.
static uint64_t	permute(uint64_t src, const uint8_t* table, size_t out_bits, size_t in_bits) {
	uint64_t	dst = 0;
	for (size_t i = 0; i < out_bits; ++i) {
		dst <<= 1;
		dst |= (src >> (in_bits - table[i])) & 1;
	}
	return dst;
}

// 28bit 値の左巡回シフト
static uint32_t	rotl28(uint32_t v, uint8_t n) {
	return ((v << n) | (v >> (28 - n))) & 0x0FFFFFFF;
}

// Feistel 関数 f(R, K): E で拡大 -> サブ鍵と XOR -> S ボックス -> P で転置
static uint32_t	feistel(uint32_t r, uint64_t subkey) {
	const uint64_t	expanded = permute(r, DES_E, 48, 32) ^ subkey;
	uint32_t		out = 0;
	for (size_t j = 0; j < 8; ++j) {
		const uint8_t	six = (expanded >> (42 - 6 * j)) & 0x3F;
		const uint8_t	row = (((six >> 5) & 1) << 1) | (six & 1);
		const uint8_t	col = (six >> 1) & 0x0F;
		out = (out << 4) | DES_S[j][row][col];
	}
	return permute(out, DES_P, 32, 32);
}

t_des_subkeys	des_key_schedule(uint64_t key) {
	const uint64_t	permuted = permute(key, DES_PC1, 56, 64);
	uint32_t		c = (permuted >> 28) & 0x0FFFFFFF;
	uint32_t		d = permuted & 0x0FFFFFFF;
	t_des_subkeys	subkeys;
	for (size_t i = 0; i < DES_ROUNDS; ++i) {
		c = rotl28(c, DES_SHIFT[i]);
		d = rotl28(d, DES_SHIFT[i]);
		const uint64_t	cd = ((uint64_t)c << 28) | d;
		subkeys.k[i] = permute(cd, DES_PC2, 48, 56);
	}
	return subkeys;
}

uint64_t	des_crypt_block(uint64_t block, const t_des_subkeys* subkeys, bool decrypt) {
	const uint64_t	permuted = permute(block, DES_IP, 64, 64);
	uint32_t		l = (permuted >> 32) & 0xFFFFFFFF;
	uint32_t		r = permuted & 0xFFFFFFFF;
	for (size_t i = 0; i < DES_ROUNDS; ++i) {
		// 復号時はサブ鍵を逆順に適用する
		const size_t	index = decrypt ? (DES_ROUNDS - 1 - i) : i;
		const uint32_t	next = l ^ feistel(r, subkeys->k[index]);
		l = r;
		r = next;
	}
	// 最終ラウンド後は L, R を入れ替えた (R16 || L16) を最終転置に通す
	const uint64_t	preoutput = ((uint64_t)r << 32) | l;
	return permute(preoutput, DES_FP, 64, 64);
}

uint64_t	des_load_block(const uint8_t bytes[DES_BLOCK_BYTE_SIZE]) {
	uint64_t	block = 0;
	for (size_t i = 0; i < DES_BLOCK_BYTE_SIZE; ++i) {
		block = (block << OCTET_BIT_SIZE) | bytes[i];
	}
	return block;
}

void	des_store_block(uint64_t block, uint8_t bytes[DES_BLOCK_BYTE_SIZE]) {
	for (size_t i = 0; i < DES_BLOCK_BYTE_SIZE; ++i) {
		bytes[DES_BLOCK_BYTE_SIZE - 1 - i] = block & 0xFF;
		block >>= OCTET_BIT_SIZE;
	}
}
