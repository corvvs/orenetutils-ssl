#include "ft_ssl.h"

// システムのエンディアンがリトルエンディアンかどうか
int	g_is_little_endian;
// NOTE: エンディアン変換時に参照する

static t_command	get_command(const char* arg) {
	if (arg != NULL) {
		for (unsigned int i = 0; i < sizeof(g_command_pairs) / sizeof(g_command_pairs[0]); ++i) {
			if (ft_strcmp(arg, g_command_pairs[i].name) == 0) {
				return g_command_pairs[i].algo;
			}
		}
	}
	return COMMAND_UNKNOWN;
}

int main(int argc, char **argv) {
	// 最初にシステムのエンディアンを求める
	g_is_little_endian = is_little_endian();
	DEBUGOUT("g_is_little_endian: %d", g_is_little_endian);

	if (argc < 2) {
		printf("usage: ft_ssl command [command opts] [command args]\n");
		return (0);
	}
	++argv;
	const char*	command_arg = *argv;
	t_command	command = get_command(*argv);
	++argv;
	switch (command) {
		case COMMAND_MD5: {
			const char*	arg = *argv;
			size_t		arg_len = ft_strlen(arg);
			digest_md5((const uint8_t*)arg, arg_len * 8);
			break;
		}
		case COMMAND_SHA256: {
			const char*	arg = *argv;
			size_t		arg_len = ft_strlen(arg);
			digest_sha_2((const uint8_t*)arg, arg_len * 8);
			break;
		}
		default: {
			dprintf(STDERR_FILENO, "Invalid command '%s'; type \"help\" for a list.\n", command_arg);
			exit(1);
		}
	}

}
