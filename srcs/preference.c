#include "ft_ssl.h"

// ハッシュ (`md5` / `sha*`) のオプション
static const t_option_spec	g_options_digest[] = {
	{ .name = "p", .kind = OPTION_SET_TRUE, .field_offset = offsetof(t_preference_digest, is_echo) },
	{ .name = "q", .kind = OPTION_SET_TRUE, .field_offset = offsetof(t_preference_digest, is_quiet) },
	{ .name = "r", .kind = OPTION_SET_TRUE, .field_offset = offsetof(t_preference_digest, is_reverse) },
	{ .name = "s", .kind = OPTION_STRING,   .field_offset = offsetof(t_preference_digest, message_argument) },
	{ .name = NULL },
};

int	parse_options_digest(const t_master* master, char** argv, t_preference_digest* pref_ptr) {
	t_preference_digest	pref = {};
	const int	parsed_count = parse_options(master, argv, &pref, g_options_digest);
	if (parsed_count < 0) {
		return -1;
	}
	*pref_ptr = pref;
	return parsed_count;
}
