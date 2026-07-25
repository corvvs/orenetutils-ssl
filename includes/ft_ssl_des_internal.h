#ifndef FT_SSL_DES_INTERNAL_H
#define FT_SSL_DES_INTERNAL_H

#include "ft_ssl_lib.h"
#include "ft_ssl_des.h"
#include "ft_ssl_structure.h"

// DES のラウンド数
#define DES_ROUNDS 16

// -a で出力する base64 の改行幅 (OpenSSL の enc -a に合わせる)
#define DES_BASE64_LINE_LENGTH 64

// 1つの DES ブロック暗号に使う 16 ラウンド分の鍵(ラウンド鍵).
// 各ラウンド鍵は 48bit で, uint64_t の下位 48bit を使う.
typedef struct s_des_roundkeys
{
	uint64_t	k[DES_ROUNDS];
}	t_des_roundkeys;

// [ブロック連鎖モードの抽象]
// 1ブロック分の処理を表す関数. chain は CBC 等が使う連鎖状態 (直前のブロック) で,
// 呼び出しごとに次のブロック用に更新される. ECB のように連鎖しないモードは参照しない.
typedef uint64_t	(des_block_function)(uint64_t block, const t_des_roundkeys* roundkeys, uint64_t* chain);

// 実体は des_modes.c においてモードごとに一貫性のある形で個別に定義される; この構造体を直接使うことはない.
typedef struct s_des_mode
{
	const char*			name;
	des_block_function*	encrypt;
	des_block_function*	decrypt;
	bool				uses_iv;	// 初期化ベクトル (-v) を使うか
}	t_des_mode;

extern const t_des_mode	g_des_mode_ecb;

// 64bit 鍵から 16 ラウンド分のラウンド鍵を生成する.
t_des_roundkeys	des_key_schedule(uint64_t key);
// 64bit ブロック 1 つを暗号化 (decrypt=false) または復号 (decrypt=true) する.
uint64_t		des_crypt_block(uint64_t block, const t_des_roundkeys* roundkeys, bool decrypt);
// ビッグエンディアンのオクテット列を 64bit ブロックに読み込む / 書き出す.
uint64_t		des_load_block(const uint8_t bytes[DES_BLOCK_BYTE_SIZE]);
void			des_store_block(uint64_t block, uint8_t bytes[DES_BLOCK_BYTE_SIZE]);

// -k で与えられた 16 進文字列を 64bit 鍵として解釈し, ラウンド鍵を生成する.
t_des_roundkeys	des_roundkeys_from_hex(const char* hex);

// モードを差し替えるだけで各 des-* コマンドを実現する共通フロントエンド.
int	run_des_generic(t_master* master, char** argv, const t_des_mode* mode);

#endif
