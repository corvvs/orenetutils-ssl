#ifndef FT_SSL_DES_INTERNAL_H
#define FT_SSL_DES_INTERNAL_H

#include "ft_ssl_lib.h"
#include "ft_ssl_des.h"

// DES のラウンド数
#define DES_ROUNDS 16

// 1つの DES ブロック暗号に使う 16 ラウンド分のサブ鍵.
// 各サブ鍵は 48bit で, uint64_t の下位 48bit を使う.
typedef struct s_des_subkeys
{
	uint64_t	k[DES_ROUNDS];
}	t_des_subkeys;

// des_core.c
// 64bit 鍵から 16 ラウンド分のサブ鍵を生成する.
t_des_subkeys	des_key_schedule(uint64_t key);
// 64bit ブロック 1 つを暗号化 (decrypt=false) または復号 (decrypt=true) する.
uint64_t		des_crypt_block(uint64_t block, const t_des_subkeys* subkeys, bool decrypt);
// ビッグエンディアンのオクテット列を 64bit ブロックに読み込む / 書き出す.
uint64_t		des_load_block(const uint8_t bytes[DES_BLOCK_BYTE_SIZE]);
void			des_store_block(uint64_t block, uint8_t bytes[DES_BLOCK_BYTE_SIZE]);

#endif
