#include "ft_ssl.h"

// `des-*` / `des3-*` のオプション
static const t_option_spec	g_options_des[] = {
	{ .name = "e", .kind = OPTION_SET_FALSE, .field_offset = offsetof(t_preference_des, is_decode) },
	{ .name = "d", .kind = OPTION_SET_TRUE,  .field_offset = offsetof(t_preference_des, is_decode) },
	{ .name = "a", .kind = OPTION_SET_TRUE,  .field_offset = offsetof(t_preference_des, is_base64) },
	{ .name = "k", .kind = OPTION_STRING,    .field_offset = offsetof(t_preference_des, hex_key) },
	{ .name = "v", .kind = OPTION_STRING,    .field_offset = offsetof(t_preference_des, hex_iv) },
	{ .name = "s", .kind = OPTION_STRING,    .field_offset = offsetof(t_preference_des, hex_salt) },
	{ .name = "p", .kind = OPTION_STRING,    .field_offset = offsetof(t_preference_des, password) },
	{ .name = "i", .kind = OPTION_STRING,    .field_offset = offsetof(t_preference_des, path_input) },
	{ .name = "o", .kind = OPTION_STRING,    .field_offset = offsetof(t_preference_des, path_output) },
	{ .name = NULL },
};

int	parse_options_des(const t_master* master, char** argv, t_preference_des* pref_ptr) {
	t_preference_des	pref = {};
	const int	parsed_count = parse_options(master, argv, &pref, g_options_des);
	if (parsed_count < 0) {
		return -1;
	}
	*pref_ptr = pref;
	return parsed_count;
}
