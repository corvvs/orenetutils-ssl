#include "ft_ssl.h"

// システムのエンディアンがリトルエンディアンかどうか
int	g_is_little_endian;
// NOTE: エンディアン変換時に参照する

int main(int argc, char **argv) {
	// 最初にシステムのエンディアンを求める
	g_is_little_endian = is_little_endian();
	DEBUGOUT("g_is_little_endian: %d", g_is_little_endian);

	if (argc < 2) {
		printf("usage: ft_ssl command [command opts] [command args]\n");
		return (0);
	}
	const char*	arg = argv[1];
	size_t		arg_len = ft_strlen(arg);

	digest_sha_2((const uint8_t*)arg, arg_len * 8);
	// digest_md5((const uint8_t*)arg, arg_len * 8);
}
