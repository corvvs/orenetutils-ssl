#include "ft_ssl_des_internal.h"

// [DES ブロック暗号のコア]
// FIPS 46-3 の各テーブルを 1-indexed (MSB=1) のまま持ち, permute() で駆動する.

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

// Feistel 拡大置換 E (32 -> 48)
static const uint8_t	DES_E[48] = {
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1,
};

// Feistel 転置 P (32 -> 32)
static const uint8_t	DES_P[32] = {
	16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
	 2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25,
};

// 鍵スケジュール PC-1 (64 -> 56)
static const uint8_t	DES_PC1[56] = {
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
};

// 鍵スケジュール PC-2 (56 -> 48)
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

// Feistel S ボックス S1 .. S8
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
// ** 呼び出す時は PERMUTE_XXX マクロを使うこと **
static uint64_t	permute(uint64_t src, const uint8_t* table, size_t out_bits, size_t in_bits) {
	uint64_t	dst = 0;
	for (size_t i = 0; i < out_bits; ++i) {
		dst <<= 1;
		dst |= (src >> (in_bits - table[i])) & 1;
	}
	return dst;
}

// これは使わない
#define PERMUTE(src, table, in_bits) permute((src), (table), sizeof(table) / sizeof((table)[0]), (in_bits))
// ここから下を使う
#define PERMUTE_IP(src)   PERMUTE((src), DES_IP,  64)
#define PERMUTE_FP(src)   PERMUTE((src), DES_FP,  64)
#define PERMUTE_E(src)    PERMUTE((src), DES_E,   32)
#define PERMUTE_P(src)    PERMUTE((src), DES_P,   32)
#define PERMUTE_PC1(src)  PERMUTE((src), DES_PC1, 64)
#define PERMUTE_PC2(src)  PERMUTE((src), DES_PC2, 56)

// 28bit 値の左巡回シフト
static uint32_t	rotl28(uint32_t v, uint8_t n) {
	return ((v << n) | (v >> (28 - n))) & 0x0FFFFFFF;
}

// Feistel 関数 f(R, K): E で拡大 -> ラウンド鍵と XOR -> S ボックス -> P で転置
// https://ja.wikipedia.org/wiki/Data_Encryption_Standard#Feistel(F)%E9%96%A2%E6%95%B0
static uint32_t	feistel(uint32_t r, uint64_t roundkey) {
	// 入力(32bitを E(Expansion; 拡大置換)に入れて, その結果をラウンド鍵と XOR する(-> 48bit)
	const uint64_t	expanded = PERMUTE_E(r) ^ roundkey;
	// 48bit を 6bit ごとに S BOX に入れる(6bit -> 4bit)
	uint32_t		out = 0;
	for (size_t j = 0; j < 8; ++j) {
		const uint8_t	six = (expanded >> (6*(7 - j)) ) & 0x3F;
		const uint8_t	row = (((six >> 5) & 1) << 1) | (six & 1);
		const uint8_t	col = (six >> 1) & 0x0F;
		out = (out << 4) | DES_S[j][row][col];
	}
	// 結果(4bit * 8 = 32bit)を結合し, P(Permutation; 転置)に入れる(-> 32bit)
	return PERMUTE_P(out);
}

// ラウンド鍵生成
// https://ja.wikipedia.org/wiki/Data_Encryption_Standard#%E9%8D%B5%E3%82%B9%E3%82%B1%E3%82%B8%E3%83%A5%E3%83%BC%E3%83%AB
t_des_roundkeys	des_key_schedule(uint64_t key) {
	const uint64_t	permuted = PERMUTE_PC1(key);
	// PC-1で得られた56ビットを左右28ビット(c, d)に分割
	uint32_t		c = (permuted >> 28) & 0x0FFFFFFF;
	uint32_t		d = permuted & 0x0FFFFFFF;
	t_des_roundkeys	roundkeys;
	for (size_t i = 0; i < DES_ROUNDS; ++i) {
		// ラウンド単位ローテーション
		c = rotl28(c, DES_SHIFT[i]);
		d = rotl28(d, DES_SHIFT[i]);
		// 左右を結合
		const uint64_t	cd = ((uint64_t)c << 28) | d;
		// PC-2 で 48bit ラウンド鍵を生成
		roundkeys.k[i] = PERMUTE_PC2(cd);
	}
	return roundkeys;
}

// https://ja.wikipedia.org/wiki/Data_Encryption_Standard#%E5%85%A8%E4%BD%93%E6%A7%8B%E9%80%A0
uint64_t	des_crypt_block(uint64_t block, const t_des_roundkeys* roundkeys, t_des_direction direction) {
	// IP を実施
	const uint64_t	permuted = PERMUTE_IP(block);
	// IP で得られた64ビットを左右32ビット(l, rs)に分割
	uint32_t		l = (permuted >> 32) & 0xFFFFFFFF;
	uint32_t		r = permuted & 0xFFFFFFFF;
	// 16 ラウンドの Feistel 構造を実施
	for (size_t i = 0; i < DES_ROUNDS; ++i) {
		// 復号時はラウンド鍵を逆順に適用する
		const size_t	rk_i = (direction == DES_DECRYPT) ? (DES_ROUNDS - 1 - i) : i;
		// r だけに F(Feistel)関数を適用し, l と XOR して次のラウンドの r を得る
		const uint32_t	next = l ^ feistel(r, roundkeys->k[rk_i]);
		// 次のラウンドの l は r そのもの
		l = r;
		r = next;
	}
	// 最終ラウンド後は本来 l, r の入れ替えをしないので, もう1回余計に入れ替える
	const uint64_t	preoutput = ((uint64_t)r << 32) | l;
	// FP に入れて終わり
	return PERMUTE_FP(preoutput);
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
