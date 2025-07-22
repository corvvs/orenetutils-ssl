#include "ft_ssl.h"
#include "generic_message.h"

uint64_t	hex_to_u64(char ch) {
	if ('0' <= ch && ch <= '9') {
		return ch - '0';
	} else if ('a' <= ch && ch <= 'f') {
		return ch - 'a' + 10;
	} else if ('A' <= ch && ch <= 'F') {
		return ch - 'A' + 10;
	} else {
		return 0;
	}
}

bool	scan_hexstr_to_u64(const char* hexstr, size_t byte_len, uint64_t* ptr) {
	uint64_t	val = 0;
	for (size_t i = 0; i < byte_len * 2; i++) {
		val <<= 4;
		val |= hex_to_u64(hexstr[i]);
	}
	*ptr = val;
	return true;
}

void	derive_salt(const t_master_des* master, t_des_parameters* parameter) {
	if (master->pref.message_salt) {
		// TODO: 長さチェック
		// TODO: 文字チェック
		uint64_t	salt;
		scan_hexstr_to_u64(master->pref.message_salt, DES_SALT_BYTE_LEN, &salt);
		parameter->salt = salt;
	} else {
		// rand() 2回で 64bit の乱数を生成
		// TODO: この手法は非常にまずい, HMACを使うこと
		parameter->salt = rand();
		parameter->salt <<= 32;
		parameter->salt |= rand();
	}
}

t_generic_message	derive_key_iv(const t_master_des* master, const t_des_parameters* parameter, size_t key_byte_len) {
	const t_generic_message	pp = wrap_str_generic_message(master->pref.message_passphrase);
	const t_generic_message	salt = wrap_mem_generic_message((void*)&parameter->salt, sizeof(uint64_t));
	t_generic_message	key_iv = prf_pbkdf2(master->pref.prf, &pp, &salt, 10000, key_byte_len + DES_IV_BYTE_LEN);
	return key_iv;
}

// DES のコア処理に使うパラメータを算出する
// - ソルト
//   - 与えられていた場合: それを使う
//   - 与えられていなかった場合: 乱数で生成する
//     - 乱数生成した場合, 出力する暗号データの先頭に`Salted__********`という形でソルトを埋め込む
// - 鍵
//   - 与えられていた場合: それを使う
//   - 与えられていなかった場合:
//      - パスフレーズが与えられている場合: パスフレーズとソルトからPRFで生成する
//      - パスフレーズが与えられていない場合: 対話的に入力させる
// - 初期化ベクトル
//   - 与えられていた場合: それを使う
//   - 与えられていなかった場合:
//      - パスフレーズが与えられている場合: パスフレーズとソルトからPRFで生成する
//      - パスフレーズが与えられていない場合:
//          - 初期化ベクトルが不要なモードの場合: スルー
//          - 初期化ベクトルが必要なモードの場合: 初期化ベクトル未定義エラー
// bool	des_derive_parameter(
// 	const t_master_des* master,
// 	t_des_parameters* param_ptr,
// 	size_t key_byte_len
// ) {
// 	t_des_parameters	parameter = {};

// 	const bool key_is_given = master->pref.message_key != NULL;
// 	const bool passphrase_is_given = master->pref.message_passphrase != NULL;
// 	const bool iv_is_given = master->pref.message_iv != NULL;

// 	// derive Salt
// 	derive_salt(master, &parameter);
// 	t_generic_message	key_iv = FAILED_GENERIC_MESSAGE;

// 	// derive Key + InitializeVector
// 	if (passphrase_is_given) {
// 		// パスフレーズから鍵生成を行う
// 		// 鍵の長さは, ブロック鍵 + 初期化ベクトル
// 		key_iv = derive_key_iv(master, &parameter, key_byte_len);
// 	}

// 	// derive Key
// 	if (key_is_given) {
// 		uint64_t	key;
// 		scan_hexstr_to_u64(master->pref.message_key, DES_KEY_BYTE_LEN, &key);
// 		parameter.block_key = key;
// 	} else if (passphrase_is_given) {
// 		new_generic_message(DES_KEY_BYTE_LEN);
// 	}

// 	// derive InitializeVector
	

// 	return true;
// }

