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

	if (pref->is_decode) {
		return base64_decode(&m);
	} else {
		return base64_encode(&m);
	}
	(void)argv;
	return 0;
}
