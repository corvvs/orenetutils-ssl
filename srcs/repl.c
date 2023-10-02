#include "ft_ssl.h"
#define READ_SIZE 4096

static ssize_t	memlen_until_nl(unsigned char* buffer, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		if (buffer[i] == '\n') {
			return i;
		}
	}
	return -1;
}

static ssize_t	read_command_line(t_master* master) {
	size_t	command_candidate_len = 0;
	t_elastic_buffer*	repl_buffer = &master->repl;
	// すでにバッファ内にnlがないかどうか見る
	if (repl_buffer->used > 0) {
		ssize_t	nl_len = memlen_until_nl(repl_buffer->buffer, repl_buffer->used);
		if (0 <= nl_len) {
			return nl_len;
		}
	}

	unsigned char	read_buffer[READ_SIZE];
	while (!repl_buffer->eof_reached) {
		ssize_t	read_size = read(STDIN_FILENO, read_buffer, sizeof(read_buffer));
		if (read_size < 0) {
			PRINT_ERROR(master, "%s\n", strerror(errno));
			free(repl_buffer->buffer);
			return -1;
		}
		if (read_size == 0) {
			repl_buffer->eof_reached = true;
			break;
		}
		// 読み取ったデータを elastic_buffer に追加する
		errno = 0;
		if (!eb_push(repl_buffer, read_buffer, read_size, sizeof(read_buffer))) {
			PRINT_ERROR(master, "%s\n", strerror(errno));
			free(repl_buffer->buffer);
			return -1;
		}
		ssize_t	nl_len = memlen_until_nl(read_buffer, read_size);
		if (0 <= nl_len) {
			command_candidate_len += nl_len;
			break;
		}
		command_candidate_len = repl_buffer->used;
	}
	return command_candidate_len;
}

int run_in_repl(t_master* master) {
	int					status = 0;
	t_elastic_buffer	*repl_buf = &master->repl;
	master->in_repl = true;

	while (true) {
		// show prompt
		yoyo_dprintf(STDOUT_FILENO, "%s> ", master->program_name);

		ssize_t	command_candidate_len = read_command_line(master);
		if (command_candidate_len < 0) {
			status = 1;
			break;
		}

		// NUL終端作業
		if (repl_buf->eof_reached) {
			errno = 0;
			if (!eb_push(repl_buf, "\0", 1, 1)) {
				PRINT_ERROR(master, "%s\n", strerror(errno));
				status = 1;
				break;
			}
		} else {
			((char*)repl_buf->buffer)[command_candidate_len] = '\0';
		}

		char**	arguments = ft_split(repl_buf->buffer, ' ');
		if (arguments == NULL) {
			// split 失敗
			PRINT_ERROR(master, "%s\n", strerror(errno));
			status = 1;
			break;
		}
		eb_truncate_front(repl_buf, command_candidate_len + 1);

		const char*	command_name = *arguments;
		run_command(master, command_name, arguments + 1);
		ft_destroy_splitted(arguments);

		repl_buf->eof_reached = repl_buf->eof_reached || master->stdin_eof_reached;
		if (command_name == NULL && repl_buf->eof_reached && repl_buf->used == 0) {
			// REPL終了
			break;
		}
	}

	free(repl_buf->buffer);
	return status;
}
