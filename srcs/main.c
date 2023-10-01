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

static ssize_t	memlen_until_nl(unsigned char* buffer, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		if (buffer[i] == '\n') {
			return i;
		}
	}
	return -1;
}

int main(int argc, char **argv) {
	(void)argc;
	// 最初にシステムのエンディアンを求める
	g_is_little_endian = is_little_endian();
	DEBUGOUT("g_is_little_endian: %d", g_is_little_endian);

	t_master	master = {
		.program_name = *argv,
	};
	++argv;
	if (*argv == NULL) {
		// REPL mode
		unsigned char	read_buffer[4096];
		t_elastic_buffer	repl_buffer = {
			.capacity = sizeof(read_buffer),
			.buffer = malloc(sizeof(read_buffer)),
		};
		if (repl_buffer.buffer == NULL) {
			PRINT_ERROR(&master, "%s\n", strerror(errno));
			return 1;
		}
		while (!repl_buffer.eof_reached || repl_buffer.used > 0) {
			// show prompt
			yoyo_dprintf(STDOUT_FILENO, "ft_ssl> ");
			// refrech buffer
			eb_refresh(&repl_buffer);

			ssize_t	command_candidate_len = 0;
			while (true) {
				ssize_t	read_size = read(STDIN_FILENO, read_buffer, sizeof(read_buffer));
				if (read_size < 0) {
					PRINT_ERROR(&master, "%s\n", strerror(errno));
					free(repl_buffer.buffer);
					return 1;
				}
				if (read_size == 0) {
					repl_buffer.eof_reached = true;
					break;
				}
				// 読み取ったデータを elastic_buffer に追加する
				errno = 0;
				if (!eb_push(&repl_buffer, read_buffer, read_size, sizeof(read_buffer))) {
					PRINT_ERROR(&master, "%s\n", strerror(errno));
					free(repl_buffer.buffer);
					return 1;
				}
				ssize_t	nl_len = memlen_until_nl(read_buffer, read_size);
				if (0 <= nl_len) {
					command_candidate_len += nl_len;
					break;
				}
				command_candidate_len = repl_buffer.used;
			}
			if (repl_buffer.eof_reached) {
			errno = 0;
			if (!eb_push(&repl_buffer, "\0", 1, 1)) {
				PRINT_ERROR(&master, "%s\n", strerror(errno));
				free(repl_buffer.buffer);
				return (1);
			}
			} else {
				((char*)repl_buffer.buffer)[command_candidate_len] = '\0';
			}
			char*	command_arg = ft_strdup(repl_buffer.buffer);
			if (command_arg == NULL) {
				PRINT_ERROR(&master, "%s\n", strerror(errno));
				free(repl_buffer.buffer);
				return 1;
			}
			DEBUGINFO("command_candidate_len: %zd", command_candidate_len);
			DEBUGINFO("repl_buffer.used: %zu", repl_buffer.used);
			DEBUGINFO("repl_buffer.capacity: %zu", repl_buffer.capacity);
			DEBUGINFO("command_arg: \"%s\"", command_arg);
			eb_truncate_front(&repl_buffer, command_candidate_len + 1);
			DEBUGINFO("repl_buffer.used: %zu", repl_buffer.used);
			DEBUGINFO("repl_buffer.capacity: %zu", repl_buffer.capacity);
			master.command = get_command(command_arg);
			master.command_name = command_arg;
			run_command(&master, argv);
			free(command_arg);
		}

	} else {
		// ARGV mode
		const char*	command_arg = *argv;
		master.command = get_command(command_arg);
		master.command_name = command_arg;
		++argv;

		return run_command(&master, argv);
	}
}
