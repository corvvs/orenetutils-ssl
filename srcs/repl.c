#include "ft_ssl.h"

static ssize_t	memlen_until_nl(unsigned char* buffer, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		if (buffer[i] == '\n') {
			return i;
		}
	}
	return -1;
}

int run_in_repl(t_master* master) {
	master->in_repl = true;
	unsigned char	read_buffer[4096];
	if (!eb_init(&master->repl, sizeof(read_buffer))) {
		PRINT_ERROR(master, "%s\n", strerror(errno));
		free(master->repl.buffer);
		return 1;
	}
	while (true) {
		// show prompt
		yoyo_dprintf(STDOUT_FILENO, "%s> ", master->program_name);

		ssize_t	command_candidate_len = 0;
		while (!master->repl.eof_reached) {
			ssize_t	read_size = read(STDIN_FILENO, read_buffer, sizeof(read_buffer));
			if (read_size < 0) {
				PRINT_ERROR(master, "%s\n", strerror(errno));
				free(master->repl.buffer);
				return 1;
			}
			if (read_size == 0) {
				master->repl.eof_reached = true;
				break;
			}
			// 読み取ったデータを elastic_buffer に追加する
			errno = 0;
			if (!eb_push(&master->repl, read_buffer, read_size, sizeof(read_buffer))) {
				PRINT_ERROR(master, "%s\n", strerror(errno));
				free(master->repl.buffer);
				return 1;
			}
			ssize_t	nl_len = memlen_until_nl(read_buffer, read_size);
			if (0 <= nl_len) {
				command_candidate_len += nl_len;
				break;
			}
			command_candidate_len = master->repl.used;
		}

		// NUL終端作業
		if (master->repl.eof_reached) {
			errno = 0;
			if (!eb_push(&master->repl, "\0", 1, 1)) {
				PRINT_ERROR(master, "%s\n", strerror(errno));
				free(master->repl.buffer);
				return 1;
			}
		} else {
			((char*)master->repl.buffer)[command_candidate_len] = '\0';
		}

		char**	pseudo_argv = ft_split(master->repl.buffer, ' ');
		if (pseudo_argv == NULL) {
			PRINT_ERROR(master, "%s\n", strerror(errno));
			free(master->repl.buffer);
			return 1;
		}
		const char*	command_arg = *pseudo_argv;
		eb_truncate_front(&master->repl, command_candidate_len + 1);
		if (command_arg == NULL) {
			free(pseudo_argv);
			if (master->repl.eof_reached && master->repl.used == 0) {
				free(master->repl.buffer);
				break;
			}
		} else {
			master->command = get_command(command_arg);
			master->command_name = command_arg;
			run_command(master, pseudo_argv + 1);
			master->repl.eof_reached = master->repl.eof_reached || master->stdin_eof_reached;
			ft_destroy_splitted(pseudo_argv);
		}

		// refresh buffer
		eb_refresh(&master->repl);
	}
	return 0;
}
