#ifndef FT_SSL_DES_COMMON_H
#define FT_SSL_DES_COMMON_H

// モードごとのコマンド関数を定義する.
// define_des_runner(ecb) -> run_des_ecb
// define_des_runner(cbc) -> run_des_cbc
#define define_des_runner(mode_type)                                   \
	int run_des_##mode_type(t_master *master, char **argv)              \
	{                                                                  \
		return run_des_generic(master, argv, &g_des_mode_##mode_type); \
	}

#endif
