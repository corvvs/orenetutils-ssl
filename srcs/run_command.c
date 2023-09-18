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

static void	destroy_message(t_message* message) {
	if (message->is_bytestream) {
		free(message->message);
	}
}

static int	run_digest(const t_master* master, char **argv, t_digest_func* digest_func) {
	t_master_digest	m = {
		.master = *master,
	};
	t_preference*	pref = &m.pref;
	int parsed_count = parse_options_digest(master, argv, pref);
	if (parsed_count < 0) {
		return 1;
	}
	argv += parsed_count;

	// 標準入力から
	if ((*argv == NULL && pref->message_argument == NULL) || pref->is_echo) {
		t_message	message;
		if (!create_message_stdin(master, &message)) {
			return 1;
		}
		digest_func(pref, &message);
		destroy_message(&message);
	}

	// -s から
	if (pref->message_argument != NULL) {
		t_message	message;
		if (!create_message_argument(master, &message, pref->message_argument)) {
			return 1;
		}
		digest_func(pref, &message);
		destroy_message(&message);
	}

	// ファイル(argv)から
	while (*argv != NULL) {
		t_message	message;
		if (!create_message_path(master, &message, *argv)) {
			argv += 1;
			continue;
		}
		digest_func(pref, &message);
		destroy_message(&message);
		argv += 1;
	}
	return 0;
}

static void	show_help(void) {
	yoyo_dprintf(STDERR_FILENO,
		"Commands:\n"
	);
	for (unsigned int i = 0; i < sizeof(g_command_pairs) / sizeof(g_command_pairs[0]); ++i) {
		yoyo_dprintf(STDERR_FILENO, "%s\n", g_command_pairs[i].name);
	}
	yoyo_dprintf(STDERR_FILENO, "\n");
	yoyo_dprintf(STDERR_FILENO,
		"Flags:\n"
		"-p -q -r -s\n"
	);
}

int	run_command(const t_master* master, char **argv) {
	if (master->command.func == NULL) {
		yoyo_dprintf(STDERR_FILENO, "%s: Error: '%s' is an invalid command.\n", master->program_name, master->command_name);
		yoyo_dprintf(STDERR_FILENO, "\n");
		show_help();
		return 1;
	}
	return run_digest(master, argv, master->command.func);
}
