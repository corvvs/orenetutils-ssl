#include "ft_ssl.h"

int	run_base64(t_master* master, char **argv) {
	t_master_base64	m = {
		.master = *master,
	};
	t_preference*	pref = &m.pref;
	int parsed_count = parse_options_base64(master, argv, pref);
	if (parsed_count < 0) {
		return 1;
	}
	argv += parsed_count;
	if (*argv != NULL) {
		PRINT_ERROR(master, "unexpected argument: %s\n", *argv);
		return 1;
	}

	// ここでメッセージを取得する
	int result = 0;
	const bool	open_out_fd = m.pref.path_output != NULL;
	int out_fd;
	if (open_out_fd) {
		out_fd = open(m.pref.path_output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (out_fd < 0) {
			PRINT_ERROR(master, "%s: %s\n", m.pref.path_output, strerror(errno));
		}
	} else {
		out_fd = STDOUT_FILENO;
	}

	t_elastic_buffer input = {};

	/* 標準入力から */
	if ((pref->path_input != NULL)) {
		if (!create_buffer_path(master, &input, pref->path_input)) {
			result = 1;
		}
	} else {
		if (!create_buffer_stdin(master, &input)) {
			result = 1;
		}
	}

	if (result == 0 && out_fd >= 0) {
		result = (pref->is_decode)
			? base64_decode(&m, &input, out_fd)
			: base64_encode(&m, &input, out_fd);
	}
	destroy_buffer(&input);
	if (open_out_fd && out_fd >= 0) {
		close(out_fd);
	}

	return result;
}
