#include "ft_ssl.h"

int	parse_options_base64(const t_master* master, char** argv, t_preference* pref_ptr) {
	(void)master;
	t_preference	pref = {};
	int parsed_count = 0;
	while (*argv != NULL && ft_strncmp(*argv, "-", 1) == 0) {

		const char*	option = *argv;
		++option;
		while (*option) {
			switch (*option) {
				case 'd': {
					pref.is_decode = true;
					break;
				}
				case 'e': {
					pref.is_decode = false;
					break;
				}
				// TODO: -i, -o
				default: {
					yoyo_dprintf(STDERR_FILENO, "illegal option -- %c\n", *option);
					return -1;
				}
			}
			option += 1;
		}
		argv += 1;
		parsed_count += 1;
	}
	*pref_ptr = pref;
	return parsed_count;
}

