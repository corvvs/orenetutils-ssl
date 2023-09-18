#include "ft_ssl.h"

int	parse_options_digest(const t_master* master, char** argv, t_preference* pref_ptr) {
	t_preference	pref = {};
	int parsed_count = 0;
	while (*argv != NULL && ft_strncmp(*argv, "-", 1) == 0) {

		const char*	option = *argv;
		++option;
		while (*option) {
			switch (*option) {
				case 'p': {
					pref.is_echo = true;
					break;
				}
				case 'q': {
					pref.is_quiet = true;
					break;
				}
				case 'r': {
					pref.is_reverse = true;
					break;
				}
				case 's': {
					// option に後続がある場合はアウト
					if (option[1]) {
						print_error_by_message(master, "illegal option -- s\n");
						return -1;
					}
					// argv に後続がない場合はアウト
					argv += 1;
					if (*argv == NULL) {
						print_error_by_message(master, "option requires an argument -- s\n");
						return -1;
					}
					pref.message_argument = *argv;
					parsed_count += 1;
					break;
				}
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

