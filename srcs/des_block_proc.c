#include "ft_ssl.h"
#include "generic_message.h"

// S-Box
#define DEFINE_SBOX(index, ...)\
uint8_t	des_sbox_##index(uint8_t sextet) {\
	static const uint8_t	box[64] = {__VA_ARGS__};\
	const uint8_t	row = ((sextet & 0b100000) >> 4) | (sextet & 0b000001);\
	const uint8_t	col = (sextet & 0b011110) >> 1;\
	return box[row * 16 + col];\
}

DEFINE_SBOX(1,
	14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
)
DEFINE_SBOX(2,
	15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
)
DEFINE_SBOX(3,
	10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
)
DEFINE_SBOX(4,
	7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
)
DEFINE_SBOX(5,
	2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
)
DEFINE_SBOX(6,
	12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
)
DEFINE_SBOX(7,
	4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
)
DEFINE_SBOX(8,
	13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
)

#define PICK_SEXTET(x, i) ((x) >> (48 - (i) * 6) & 0b111111)
#define PUT_QUADRUPLET(x, i) (((x) & (0b1111)) << (32 - (i) * 4))

// DES Feistel関数
// rightsideは下位32ビット, round_keyは下位48ビットを使用する.
// 返り値は下位32ビット.
uint32_t	des_elemental_feistel(uint32_t rightside, uint64_t round_key) {
	round_key = des_feistel_ep(rightside) ^ round_key;
	uint32_t	stirred = 0;
	stirred |= PUT_QUADRUPLET(des_sbox_1(PICK_SEXTET(round_key, 1)), 1);
	stirred |= PUT_QUADRUPLET(des_sbox_2(PICK_SEXTET(round_key, 2)), 2);
	stirred |= PUT_QUADRUPLET(des_sbox_3(PICK_SEXTET(round_key, 3)), 3);
	stirred |= PUT_QUADRUPLET(des_sbox_4(PICK_SEXTET(round_key, 4)), 4);
	stirred |= PUT_QUADRUPLET(des_sbox_5(PICK_SEXTET(round_key, 5)), 5);
	stirred |= PUT_QUADRUPLET(des_sbox_6(PICK_SEXTET(round_key, 6)), 6);
	stirred |= PUT_QUADRUPLET(des_sbox_7(PICK_SEXTET(round_key, 7)), 7);
	stirred |= PUT_QUADRUPLET(des_sbox_8(PICK_SEXTET(round_key, 8)), 8);
	stirred = des_feistel_p(stirred);
	return stirred;
}

#define UINT32_MASK ((1ull << 32) - 1)

#define ROUND_DES(l, r, t, index) {\
	t = l ^ des_elemental_feistel(r, round_keys->keys[index - 1]);\
	l = r;\
	r = t;\
}

// シングルDES ブロック暗号化
uint64_t	des_be1(uint64_t block_input, const t_des_round_keys* round_keys) {
	// 初期置換
	block_input = des_elemental_ip(block_input);

	// 左右32ずつに分割
	uint32_t	leftside = (block_input >> 32) & UINT32_MASK;
	uint32_t	rightside = block_input & UINT32_MASK;
	uint32_t	temp;

	// 16ラウンド
	ROUND_DES(leftside, rightside, temp, 1)
	ROUND_DES(leftside, rightside, temp, 2)
	ROUND_DES(leftside, rightside, temp, 3)
	ROUND_DES(leftside, rightside, temp, 4)
	ROUND_DES(leftside, rightside, temp, 5)
	ROUND_DES(leftside, rightside, temp, 6)
	ROUND_DES(leftside, rightside, temp, 7)
	ROUND_DES(leftside, rightside, temp, 8)
	ROUND_DES(leftside, rightside, temp, 9)
	ROUND_DES(leftside, rightside, temp, 10)
	ROUND_DES(leftside, rightside, temp, 11)
	ROUND_DES(leftside, rightside, temp, 12)
	ROUND_DES(leftside, rightside, temp, 13)
	ROUND_DES(leftside, rightside, temp, 14)
	ROUND_DES(leftside, rightside, temp, 15)
	ROUND_DES(leftside, rightside, temp, 16)

	// 左右を合成
	block_input = ((uint64_t)leftside << 32) | (uint64_t)rightside;

	return des_elemental_fp(block_input);
}

// シングルDES ブロック復号
uint64_t	des_bd1(uint64_t block_input, const t_des_round_keys* round_keys) {
	// 初期置換
	block_input = des_elemental_ip(block_input);

	// 左右32ずつに分割
	uint32_t	leftside = (block_input >> 32) & UINT32_MASK;
	uint32_t	rightside = block_input & UINT32_MASK;
	uint32_t	temp;

	// 16ラウンド; 暗号化とは逆順に鍵を使用する
	ROUND_DES(leftside, rightside, temp, 16)
	ROUND_DES(leftside, rightside, temp, 15)
	ROUND_DES(leftside, rightside, temp, 14)
	ROUND_DES(leftside, rightside, temp, 13)
	ROUND_DES(leftside, rightside, temp, 12)
	ROUND_DES(leftside, rightside, temp, 11)
	ROUND_DES(leftside, rightside, temp, 10)
	ROUND_DES(leftside, rightside, temp, 9)
	ROUND_DES(leftside, rightside, temp, 8)
	ROUND_DES(leftside, rightside, temp, 7)
	ROUND_DES(leftside, rightside, temp, 6)
	ROUND_DES(leftside, rightside, temp, 5)
	ROUND_DES(leftside, rightside, temp, 4)
	ROUND_DES(leftside, rightside, temp, 3)
	ROUND_DES(leftside, rightside, temp, 2)
	ROUND_DES(leftside, rightside, temp, 1)

	// 左右を合成
	block_input = ((uint64_t)leftside << 32) | (uint64_t)rightside;

	return des_elemental_fp(block_input);
}

// トリプルDES ブロック暗号化
uint64_t	des_be3(uint64_t block_input, const t_des_round_keys* round_keys) {
	// E1 - D2 - E3
	block_input = des_be1(block_input, &round_keys[0]);
	block_input = des_bd1(block_input, &round_keys[1]);
	block_input = des_be1(block_input, &round_keys[2]);
	return block_input;
}

// トリプルDES ブロック復号
uint64_t	des_bd3(uint64_t block_input, const t_des_round_keys* round_keys) {
	// D3 - E2 - D1
	block_input = des_bd1(block_input, &round_keys[2]);
	block_input = des_be1(block_input, &round_keys[1]);
	block_input = des_bd1(block_input, &round_keys[0]);
	return block_input;
}
