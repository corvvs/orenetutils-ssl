#include "ft_ssl.h"
#include "generic_message.h"


#define UINT28_MASK ((1ull << 28) - 1)

// 28ビット整数値 x を n ビット左回転する
#define ROT_LEFT_28(x, n) ((((x) << (n)) | ((x) >> (28 - (n)))) & UINT28_MASK)

#define UNITE(c, d) (((c) << 28) | (d))

#define ROUND_KEY(i, n, c, d) {\
	c = ROT_LEFT_28(c, n); d = ROT_LEFT_28(d, n);\
	keys.keys[i - 1] = des_key_permutation_2(UNITE(c, d));\
}

t_des_round_keys	des_key_schedule(uint64_t master_key) {
	t_des_round_keys	keys = {0};
	// 初期置換 64 -> 56
	master_key = des_key_permutation_1(master_key);
	// 左右26ずつに分割
	uint64_t	c = (master_key >> 28) & UINT28_MASK;
	uint64_t	d = master_key & UINT28_MASK;

	// 16ラウンドの鍵を生成
	ROUND_KEY( 1, 1, c, d)
	ROUND_KEY( 2, 1, c, d)
	ROUND_KEY( 3, 2, c, d)
	ROUND_KEY( 4, 2, c, d)
	ROUND_KEY( 5, 2, c, d)
	ROUND_KEY( 6, 2, c, d)
	ROUND_KEY( 7, 2, c, d)
	ROUND_KEY( 8, 2, c, d)
	ROUND_KEY( 9, 1, c, d)
	ROUND_KEY(10, 2, c, d)
	ROUND_KEY(11, 2, c, d)
	ROUND_KEY(12, 2, c, d)
	ROUND_KEY(13, 2, c, d)
	ROUND_KEY(14, 2, c, d)
	ROUND_KEY(15, 2, c, d)
	ROUND_KEY(16, 1, c, d)

	return keys;
}
