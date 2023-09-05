#ifndef UTILS_ENDIAN_H
#define UTILS_ENDIAN_H

#include "ft_ssl_lib.h"

// エンディアン変換を行う.
// 引数 value のサイズ(1, 2, 4, 8)に応じて変換関数を自動選択する.
#define SWAP_BYTE(value) (sizeof(value) < 2 ? (value) : sizeof(value) < 4 ? swap_2byte(value) \
													: sizeof(value) < 8	  ? swap_4byte(value) \
																		  : swap_8byte(value))

// 環境がリトルエンディアンの時のみエンディアン変換を行う
// (返り値が uint64_t になることに注意)
// (使用するファイルで extern int	g_is_little_endian; すること)
#define PASS_BIG_END(value) (g_is_little_endian ? SWAP_BYTE(value) : (value))

// 環境がビッグエンディアンの時のみエンディアン変換を行う
// (返り値が uint64_t になることに注意)
// (使用するファイルで extern int	g_is_little_endian; すること)
#define PASS_LIT_END(value) (g_is_little_endian ? (value) : SWAP_BYTE(value))

bool is_little_endian(void);
uint16_t swap_2byte(uint16_t value);
uint32_t swap_4byte(uint32_t value);
uint64_t swap_8byte(uint64_t value);

#endif
