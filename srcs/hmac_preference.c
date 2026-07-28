#include "ft_ssl.h"

extern t_hmac_hash_interface	g_hi_md5;
extern t_hmac_hash_interface	g_hi_sha_224;
extern t_hmac_hash_interface	g_hi_sha_256;
extern t_hmac_hash_interface	g_hi_sha_384;
extern t_hmac_hash_interface	g_hi_sha_512;
extern t_hmac_hash_interface	g_hi_sha_512_224;
extern t_hmac_hash_interface	g_hi_sha_512_256;

static t_hmac_hash_interface*	select_hi(const char* algo_name) {
	if (ft_strcmp(algo_name, "md5") == 0) { return &g_hi_md5; }
	if (ft_strcmp(algo_name, "sha224") == 0) { return &g_hi_sha_224; }
	if (ft_strcmp(algo_name, "sha256") == 0) { return &g_hi_sha_256; }
	if (ft_strcmp(algo_name, "sha384") == 0) { return &g_hi_sha_384; }
	if (ft_strcmp(algo_name, "sha512") == 0) { return &g_hi_sha_512; }
	if (ft_strcmp(algo_name, "sha512-224") == 0) { return &g_hi_sha_512_224; }
	if (ft_strcmp(algo_name, "sha512-256") == 0) { return &g_hi_sha_512_256; }
	return NULL;
}

// -a は名前からハッシュの実体を引くので, 表に書ける代入では済まない
static bool	set_hmac_algorithm(const t_master* master, void* pref, const char* value) {
	t_hmac_hash_interface*	hi = select_hi(value);
	if (hi == NULL) {
		print_error_by_message(master, "unexpected hash algorithm name");
		return false;
	}
	((t_preference_hmac*)pref)->hi = hi;
	return true;
}

// `hmac` のオプション
static const t_option_spec	g_options_hmac[] = {
	{ .name = "a", .kind = OPTION_CUSTOM, .handle = set_hmac_algorithm },
	{ .name = "k", .kind = OPTION_STRING, .field_offset = offsetof(t_preference_hmac, path_key) },
	{ .name = NULL },
};

int	parse_options_hmac(const t_master* master, char** argv, t_preference_hmac* pref_ptr) {
	t_preference_hmac	pref = {};
	const int	parsed_count = parse_options(master, argv, &pref, g_options_hmac);
	if (parsed_count < 0) {
		return -1;
	}
	if (pref.hi == NULL) {
		// set default
		pref.hi = &g_hi_sha_256;
	}
	*pref_ptr = pref;
	return parsed_count;
}
