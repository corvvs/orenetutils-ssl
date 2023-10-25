#include "ft_ssl.h"

// システムのエンディアンがリトルエンディアンかどうか
int	g_is_little_endian;
// NOTE: エンディアン変換時に参照する

t_hmac_hash_interface	g_hi_md5;
t_hmac_hash_interface	g_hi_sha_224;
t_hmac_hash_interface	g_hi_sha_256;
t_hmac_hash_interface	g_hi_sha_384;
t_hmac_hash_interface	g_hi_sha_512;
t_hmac_hash_interface	g_hi_sha_512_224;
t_hmac_hash_interface	g_hi_sha_512_256;
bool	on_startup(void) {
	g_hi_md5 = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_md5);
	g_hi_sha_224 = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_224);
	g_hi_sha_256 = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_256);
	g_hi_sha_384 = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_384);
	g_hi_sha_512 = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_512);
	g_hi_sha_512_224 = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_512_224);
	g_hi_sha_512_256 = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_512_256);
	return true;
}

int main(int argc, char **argv) {
	(void)argc;
	// 最初にシステムのエンディアンを求める
	g_is_little_endian = is_little_endian();
	DEBUGOUT("g_is_little_endian: %d", g_is_little_endian);

	if (!on_startup()) {
		return 1;
	}

	t_master	master = {
		.program_name = *argv,
	};
	++argv;
	const char*	command_name = *argv;
	if (command_name == NULL) {
		// REPL mode
		return run_in_repl(&master);
	} else {
		// ARGV mode
		return run_command(&master, command_name, argv + 1);
	}
}
