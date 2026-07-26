#ifndef FT_SSL_DES_H
#define FT_SSL_DES_H

#include "ft_ssl_lib.h"

// DES のブロック長・鍵長 (どちらも 64bit = 8オクテット)
#define DES_BLOCK_BYTE_SIZE 8
#define DES_KEY_BYTE_SIZE 8

// Triple DES は 8 オクテットの鍵を 3 本使う
#define DES_KEYS_MAX 3
#define DES3_KEY_BYTE_SIZE (DES_KEY_BYTE_SIZE * 3)

// パスワードからの鍵導出に使う PBKDF2 の反復回数; OpenSSL 3系と合わせる
#define DES_PBKDF2_ITERATIONS 10000
#define DES_SALT_BYTE_SIZE 8

// 端末から読むパスワードの最大長
// OpenSSL も同じ長さまでを受け付ける(それより長い入力はサイレントに切り詰める)
#define DES_PASSWORD_MAX_LEN 1023

// salt をランダム生成した場合, 暗号文の先頭に"Salted__" + salt(8オクテット) を置く
// OpenSSL 3系と合わせる
#define DES_SALT_MAGIC "Salted__"
#define DES_SALT_MAGIC_BYTE_SIZE 8
#define DES_SALT_HEADER_BYTE_SIZE (DES_SALT_MAGIC_BYTE_SIZE + DES_SALT_BYTE_SIZE)

#endif
