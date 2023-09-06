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

bool	create_message_fd(t_message* message_ptr, int fd) {
	t_elastic_buffer	message_buffer;
	if (!read_file(fd, &message_buffer)) {
		return false;
	}
	if (message_buffer.buffer == NULL) {
		return false;
	}
	*message_ptr = (t_message){
		.file_path = NULL,
		.is_file = true,
		.message = (uint8_t*)message_buffer.buffer,
		.message_bit_len = message_buffer.used * 8,
	};
	return true;
}

bool	create_message_stdin(t_message* message_ptr) {
	return create_message_fd(message_ptr, STDIN_FILENO);
}

bool	create_message_argument(t_message* message_ptr, char *arg) {
	*message_ptr = (t_message){
		.file_path = NULL,
		.is_file = false,
		.message = (uint8_t*)arg,
		.message_bit_len = ft_strlen(arg) * 8,
	};
	return true;
}

bool	create_message_path(t_message* message_ptr, const char* path) {
	int	ifd = open(path, O_RDONLY);
	if (ifd < 0) {
		return false;
	}
	const bool result = create_message_fd(message_ptr, ifd);
	if (result) {
		message_ptr->file_path = path;
	}
	close(ifd);
	return result;
}

void	destroy_message(t_message* message) {
	if (message->is_file) {
		free(message->message);
	}
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
			t_message	message;
			if (!create_message_stdin(&message)) {
				return 1;
			}
			digest_md5(message.message, message.message_bit_len);
			destroy_message(&message);
			break;
		}
		case COMMAND_SHA256: {
			t_message	message;
			if (!create_message_stdin(&message)) {
				return 1;
			}
			digest_sha_2(message.message, message.message_bit_len);
			destroy_message(&message);
			break;
		}
		default: {
			dprintf(STDERR_FILENO, "Invalid command '%s'; type \"help\" for a list.\n", command_arg);
			exit(1);
		}
	}

}
