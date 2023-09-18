#include "ft_ssl.h"

// システムのエンディアンがリトルエンディアンかどうか
int	g_is_little_endian;
// NOTE: エンディアン変換時に参照する

static t_command_pair	get_command(const char* arg) {
	size_t n = sizeof(g_command_pairs) / sizeof(g_command_pairs[0]);
	if (arg != NULL) {
		for (unsigned int i = 0; i < n; ++i) {
			if (g_command_pairs[i].name == NULL) {
				break;
			}
			if (ft_strcmp(arg, g_command_pairs[i].name) == 0) {
				return g_command_pairs[i];
			}
		}
	}
	return g_command_pairs[n - 1];
}

int main(int argc, char **argv) {
	// 最初にシステムのエンディアンを求める
	g_is_little_endian = is_little_endian();
	DEBUGOUT("g_is_little_endian: %d", g_is_little_endian);

	if (argc < 2) {
		yoyo_dprintf(STDOUT_FILENO, "usage: ft_ssl command [command opts] [command args]\n");
		return (0);
	}
	t_master	master = {
		.program_name = *argv,
	};
	++argv;

	const char*	command_arg = *argv;
	master.command = get_command(command_arg);
	master.command_name = command_arg;
	++argv;

	return run_command(&master, argv);
}
