#include "ft_ssl.h"

// `base64` のオプション.
// -d と -e は同じフィールドを逆向きに設定するので, 後に書いた方が勝つ.
static const t_option_spec	g_options_base64[] = {
	{ .name = "d", .kind = OPTION_SET_TRUE,  .field_offset = offsetof(t_preference_base64, is_decode) },
	{ .name = "e", .kind = OPTION_SET_FALSE, .field_offset = offsetof(t_preference_base64, is_decode) },
	{ .name = "i", .kind = OPTION_STRING,    .field_offset = offsetof(t_preference_base64, path_input) },
	{ .name = "o", .kind = OPTION_STRING,    .field_offset = offsetof(t_preference_base64, path_output) },
	{ .name = NULL },
};

int	parse_options_base64(const t_master* master, char** argv, t_preference_base64* pref_ptr) {
	t_preference_base64	pref = {};
	const int	parsed_count = parse_options(master, argv, &pref, g_options_base64);
	if (parsed_count < 0) {
		return -1;
	}
	*pref_ptr = pref;
	return parsed_count;
}
