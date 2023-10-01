#include "ft_ssl.h"

static bool	create_message_fd(t_master* master, t_message* message_ptr, int fd) {
	t_elastic_buffer	message_buffer;
	if (master->in_repl) {
		message_buffer = master->repl;
	} else {
		if (!eb_init(&message_buffer, READ_BUFFER_SIZE)) {
			PRINT_ERROR(master, "%s\n", strerror(errno));
			return false;
		}
	}
	bool	result;
	if (!read_file(master, fd, &message_buffer)) {
		result = false;
	} else if (message_buffer.buffer == NULL) {
		result = false;
	} else {
		*message_ptr = (t_message){
			.file_path = NULL,
			.is_bytestream = true,
			.message = (uint8_t*)message_buffer.buffer,
			.message_bit_len = message_buffer.used * 8,
		};
		result = true;
	}
	if (message_buffer.eof_reached) {
		master->stdin_eof_reached = true;
	}
	return result;
}

bool	create_message_stdin(t_master* master, t_message* message_ptr) {
	return create_message_fd(master, message_ptr, STDIN_FILENO);
}

bool	create_message_argument(const t_master* master, t_message* message_ptr, char *arg) {
	(void)master;
	*message_ptr = (t_message){
		.file_path = NULL,
		.is_bytestream = false,
		.message = (uint8_t*)arg,
		.message_bit_len = ft_strlen(arg) * 8,
	};
	return true;
}

bool	create_message_path(t_master* master, t_message* message_ptr, const char* path) {
	int	ifd = open(path, O_RDONLY);
	if (ifd < 0) {
		PRINT_ERROR(master, "%s: %s\n", path, strerror(errno));
		return false;
	}
	const bool result = create_message_fd(master, message_ptr, ifd);
	if (result) {
		message_ptr->file_path = path;
	}
	close(ifd);
	return result;
}

void	destroy_message(t_message* message) {
	if (message->is_bytestream) {
		free(message->message);
	}
}
