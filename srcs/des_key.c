#include "ft_ssl_des_internal.h"

// [DES の鍵・初期化ベクトルの準備]
// (パスワードからの鍵導出は今後ここに追加する)

// 16進数字 1 文字を 0..15 に変換する. 変換できなければ -1.
static int	des_hex_value(char c) {
	c = ft_tolower(c);
	if ('0' <= c && c <= '9') {
		return c - '0';
	}
	if ('a' <= c && c <= 'f') {
		return c - 'a' + 10;
	}
	return -1;
}

// 16 進文字列を 64bit のオクテット列へ変換する.
// 短ければ右側をゼロ埋め, 長ければ切り詰める (OpenSSL の挙動に合わせる).
// 奇数桁の末尾は上位ニブルとして扱う (例: "FF1" -> FF 10 00 ..).
static void	des_hex_to_block(const char* hex, uint8_t block[DES_BLOCK_BYTE_SIZE]) {
	ft_bzero(block, DES_BLOCK_BYTE_SIZE);
	size_t	bi = 0;
	size_t	i = 0;
	while (hex[i] && bi < DES_BLOCK_BYTE_SIZE) {
		const int	hi = des_hex_value(hex[i]);
		if (hi < 0) {
			break;
		}
		++i;
		int	lo = 0;
		if (hex[i]) {
			const int	v = des_hex_value(hex[i]);
			if (v >= 0) {
				lo = v;
				++i;
			}
		}
		block[bi++] = (hi << 4) | lo;
	}
}

uint64_t	des_block_from_hex(const char* hex) {
	uint8_t	block[DES_BLOCK_BYTE_SIZE];
	des_hex_to_block(hex, block);
	return des_load_block(block);
}

t_des_roundkeys	des_roundkeys_from_hex(const char* hex) {
	return des_key_schedule(des_block_from_hex(hex));
}
