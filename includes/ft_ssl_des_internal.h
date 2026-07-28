#ifndef FT_SSL_DES_INTERNAL_H
#define FT_SSL_DES_INTERNAL_H

#include "ft_ssl_lib.h"
#include "ft_ssl_des.h"
#include "ft_ssl_structure.h"

// DES のラウンド数
#define DES_ROUNDS 16

// 暗号本体を通す向き. 暗号化と復号は同じ関数で扱い, この値で区別する.
typedef enum e_des_direction
{
	DES_ENCRYPT,
	DES_DECRYPT,
}	t_des_direction;

// 1つの DES ブロック暗号に使う 16 ラウンド分の鍵(ラウンド鍵).
// 各ラウンド鍵は 48bit で, uint64_t の下位 48bit を使う.
typedef struct s_des_roundkeys
{
	uint64_t	k[DES_ROUNDS];
}	t_des_roundkeys;

// 実際に使う鍵一式. DES は 1 本, Triple DES は 3 本.
typedef struct s_des_keys
{
	t_des_roundkeys	roundkeys[DES_KEYS_MAX];
	size_t			count;
}	t_des_keys;

// [ブロック暗号本体の抽象]
// 64bit ブロック 1 つを変換する. DES は 1 回, Triple DES は E-D-E の 3 回.
// 連鎖のさせ方 (下の t_des_mode) とは独立に差し替えられる.
typedef uint64_t	(des_cipher_function)(uint64_t block, const t_des_keys* keys, t_des_direction direction);

// 実体は des_ciphers.c で定義される.
typedef struct s_des_cipher
{
	const char*				name;
	des_cipher_function*	crypt;
	size_t					key_byte_size;	// 鍵材料の総バイト数 (DES:8, 3DES:24)
	size_t					key_count;		// 鍵の本数 (DES:1, 3DES:3)
}	t_des_cipher;

extern const t_des_cipher	g_des_cipher_des;
extern const t_des_cipher	g_des_cipher_des3;

// モードがブロックを変換するのに要る一式 (どの暗号本体を, どの鍵で).
typedef struct s_des_block_context
{
	const t_des_cipher*	cipher;
	const t_des_keys*	keys;
}	t_des_block_context;

// [ブロック連鎖モードの抽象]
// 1ブロック分の処理を表す関数. chain は CBC 等が使う連鎖状態 (直前のブロック) で,
// 呼び出しごとに次のブロック用に更新される. ECB のように連鎖しないモードは参照しない.
typedef uint64_t	(des_block_function)(uint64_t block, const t_des_block_context* ctx, uint64_t* chain);

// 実体は des_modes.c においてモードごとに一貫性のある形で個別に定義される; この構造体を直接使うことはない.
typedef struct s_des_mode
{
	const char*			name;
	des_block_function*	encrypt;
	des_block_function*	decrypt;
	bool				uses_iv; // 初期化ベクトル (-v) を使うか
	// ブロックを埋めてから処理するか.
	// ECB/CBC 等のブロックモードは true. OFB 等のストリームモードは false で,
	// 暗号文長が平文長と等しくなり, 末尾が 8 オクテット未満になりうる.
	bool				uses_padding;
}	t_des_mode;

extern const t_des_mode	g_des_mode_ecb;
extern const t_des_mode	g_des_mode_cbc;
extern const t_des_mode	g_des_mode_ofb;
extern const t_des_mode	g_des_mode_cfb;
extern const t_des_mode	g_des_mode_ctr;
extern const t_des_mode	g_des_mode_pcbc;

// 実際に暗号化・復号に使う鍵材料.
// -k / -v による直接指定と, パスワードからの導出のどちらでもここに集約される.
typedef struct s_des_secret
{
	t_des_keys		keys;
	uint64_t		iv;
	uint8_t			salt[DES_SALT_BYTE_SIZE];
	// 暗号文の先頭に "Salted__" + salt を置くか
	// salt をランダム生成したとき, つまり -s も -k もない暗号化のとき true になる
	bool			emit_salt_header;
}	t_des_secret;

// 64bit 鍵から 16 ラウンド分のラウンド鍵を生成する.
t_des_roundkeys	des_key_schedule(uint64_t key);
// 64bit ブロック 1 つを direction の向きに変換する.
uint64_t		des_crypt_block(uint64_t block, const t_des_roundkeys* roundkeys, t_des_direction direction);
// ビッグエンディアンのオクテット列を 64bit ブロックに読み込む / 書き出す.
uint64_t		des_load_block(const uint8_t bytes[DES_BLOCK_BYTE_SIZE]);
void			des_store_block(uint64_t block, uint8_t bytes[DES_BLOCK_BYTE_SIZE]);

// 16 進文字列を 64bit 値として解釈する (-v の初期化ベクトル用).
uint64_t		des_block_from_hex(const char* hex);
// 16 進文字列を size オクテットへ変換する (-s の salt や鍵材料用).
// 短ければゼロ埋め, 長ければ切り詰める.
void			des_bytes_from_hex(const char* hex, uint8_t* out, size_t size);
// 鍵材料 (8 オクテット × count) からラウンド鍵一式を作る.
t_des_keys		des_keys_from_bytes(const uint8_t* material, size_t count);

// salt をランダムに生成する.
bool			des_random_salt(uint8_t salt[DES_SALT_BYTE_SIZE]);
// パスワードと salt から鍵材料と IV を導出する (PBKDF2-HMAC-SHA256).
// 導出結果は先頭 key_byte_size オクテットが鍵材料, 続く 8 オクテットが IV.
bool			des_derive_key_iv(
					const char* password,
					const uint8_t salt[DES_SALT_BYTE_SIZE],
					size_t key_byte_size,
					bool needs_iv,
					uint8_t* key_material,
					uint64_t* iv);
// パスワードを得る. -p があればそれを, なければ端末 (なければ標準入力) から読む.
// 端末から読む場合は buffer に格納して返す. 失敗時は NULL (エラーは内部で報告済み).
const char*		des_acquire_password(const t_master_des* m, char* buffer, size_t size);

// 暗号本体とモードを差し替えるだけで各 des-* コマンドを実現する共通フロントエンド.
int	run_des_generic(t_master* master, char** argv, const t_des_cipher* cipher, const t_des_mode* mode);

#endif
