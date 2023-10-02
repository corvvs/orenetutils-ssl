#include "ft_ssl.h"

// システムのエンディアンがリトルエンディアンかどうか
int	g_is_little_endian;
// NOTE: エンディアン変換時に参照する

int main(int argc, char **argv) {
	(void)argc;
	// 最初にシステムのエンディアンを求める
	g_is_little_endian = is_little_endian();
	DEBUGOUT("g_is_little_endian: %d", g_is_little_endian);

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
