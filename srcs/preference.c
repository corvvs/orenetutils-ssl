#include "ft_ssl.h"
#include "ft_ssl_preference.h"

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
				PARSE_PREFERENCE_WITH_1_ARGUMENT('s', s, message_argument)
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

