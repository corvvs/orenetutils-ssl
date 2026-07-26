#ifndef FT_SSL_DES_COMMON_H
#define FT_SSL_DES_COMMON_H

// 「暗号本体 × 連鎖モード」の組み合わせごとにコマンド関数を定義する.
// define_des_runner(des_ecb,  des,  ecb) -> run_des_ecb
// define_des_runner(des3_cbc, des3, cbc) -> run_des3_cbc
#define define_des_runner(command, cipher_type, mode_type)  \
	int run_##command(t_master *master, char **argv)         \
	{                                                       \
		return run_des_generic(master, argv,                \
			&g_des_cipher_##cipher_type,                    \
			&g_des_mode_##mode_type);                       \
	}

#endif
