#include "ft_ssl.h"

static bool	create_message_fd(const t_master* master, t_message* message_ptr, int fd) {
	t_elastic_buffer	message_buffer;
	if (!read_file(master, fd, &message_buffer)) {
		return false;
	}
	if (message_buffer.buffer == NULL) {
		return false;
	}
	*message_ptr = (t_message){
		.file_path = NULL,
		.is_bytestream = true,
		.message = (uint8_t*)message_buffer.buffer,
		.message_bit_len = message_buffer.used * 8,
	};
	return true;
}

static bool	create_message_stdin(const t_master* master, t_message* message_ptr) {
	return create_message_fd(master, message_ptr, STDIN_FILENO);
}

static bool	create_message_argument(const t_master* master, t_message* message_ptr, char *arg) {
	(void)master;
	*message_ptr = (t_message){
		.file_path = NULL,
		.is_bytestream = false,
		.message = (uint8_t*)arg,
		.message_bit_len = ft_strlen(arg) * 8,
	};
	return true;
}

static bool	create_message_path(const t_master* master, t_message* message_ptr, const char* path) {
	int	ifd = open(path, O_RDONLY);
	if (ifd < 0) {
		print_error_by_errno(master);
		return false;
	}
	const bool result = create_message_fd(master, message_ptr, ifd);
	if (result) {
		message_ptr->file_path = path;
	}
	close(ifd);
	return result;
}

static void	destroy_message(t_message* message) {
	if (message->is_bytestream) {
		free(message->message);
	}
}

static int	run_digest(const t_master* master, char **argv, void (digest_func)(const t_preference*, const t_message*)) {
	t_preference	pref = {};
	int parsed_count = parse_options(master, argv, &pref);
	if (parsed_count < 0) {
		return 1;
	}
	argv += parsed_count;

	if ((*argv == NULL && pref.message_argument == NULL) || pref.is_echo) {
		t_message	message;
		if (!create_message_stdin(master, &message)) {
			return 1;
		}
		digest_func(&pref, &message);
		destroy_message(&message);
	}
	if (pref.message_argument != NULL) {
		t_message	message;
		if (!create_message_argument(master, &message, pref.message_argument)) {
			return 1;
		}
		digest_func(&pref, &message);
		destroy_message(&message);
	}

	while (*argv != NULL) {
		t_message	message;
		if (!create_message_path(master, &message, *argv)) {
			return 1;
		}
		digest_func(&pref, &message);
		destroy_message(&message);
		argv += 1;
	}
	return 0;
}

int	run_command(const t_master* master, char **argv) {
	switch (master->command) {
		case COMMAND_MD5: {
			return run_digest(master, argv, digest_md5);
		}
		case COMMAND_SHA224: {
			return run_digest(master, argv, digest_sha_224);
		}
		case COMMAND_SHA256: {
			return run_digest(master, argv, digest_sha_256);
		}
		case COMMAND_SHA384: {
			return run_digest(master, argv, digest_sha_384);
		}
		case COMMAND_SHA512: {
			return run_digest(master, argv, digest_sha_512);
		}
		case COMMAND_SHA512_256: {
			return run_digest(master, argv, digest_sha_512_256);
		}
		default: {
			dprintf(STDERR_FILENO, "Invalid command '%s'; type \"help\" for a list.\n", master->command_name);
			return 1;
		}
	}
}
