#include "ft_ssl.h"

static bool	create_buffer_fd(t_master* master, t_elastic_buffer* message_ptr, int fd, bool from_stdin) {
	t_elastic_buffer	message_buffer = {};
	if (master->in_repl && from_stdin) {
		message_buffer = eb_release(&master->repl);
	}
	bool	result;
	if (!read_file(master, fd, &message_buffer)) {
		result = false;
	} else {
		*message_ptr = message_buffer;
		message_buffer.buffer = NULL;
		result = true;
	}
	if (from_stdin && message_buffer.eof_reached) {
		master->stdin_eof_reached = true;
	}
	free(message_buffer.buffer);
	return result;
}

bool	create_buffer_stdin(t_master* master, t_elastic_buffer* message_ptr) {
	return create_buffer_fd(master, message_ptr, STDIN_FILENO, true);
}

bool	create_buffer_path(t_master* master, t_elastic_buffer* message_ptr, const char* path) {
	int	ifd = open(path, O_RDONLY);
	if (ifd < 0) {
		PRINT_ERROR(master, "%s: %s\n", path, strerror(errno));
		return false;
	}
	const bool result = create_buffer_fd(master, message_ptr, ifd, false);
	close(ifd);
	return result;
}

void	destroy_buffer(t_elastic_buffer* message) {
	free(message->buffer);
}
