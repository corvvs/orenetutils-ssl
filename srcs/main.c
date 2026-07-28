#include "ft_ssl.h"

// システムのエンディアンがリトルエンディアンかどうか
int	g_is_little_endian;
// NOTE: エンディアン変換時に参照する

// デバッグ出力を行うかどうか (DEBUG ビルドでのみ意味を持つ)
int	g_debug_enabled = 1;
// NOTE: DEBUG* マクロが参照する

int main(int argc, char **argv) {
	// argv が空の場合 (execve に空の配列を渡された場合) はプログラム名すら無い.
	// このまま進むと ++argv が argv の終端を越えて環境変数を読んでしまう.
	if (argc < 1) {
		return 1;
	}
	// デバッグ出力の有無を最初に決める (以降の DEBUG* 出力が従う)
	const char*	debug_env = getenv("FT_SSL_DEBUG");
	g_debug_enabled = (debug_env == NULL || ft_strcmp(debug_env, "0") != 0);

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
