#include "ft_ssl.h"

extern t_pbkdf2_prf	g_prf_hmac_md5;
extern t_pbkdf2_prf	g_prf_hmac_sha_224;
extern t_pbkdf2_prf	g_prf_hmac_sha_256;
extern t_pbkdf2_prf	g_prf_hmac_sha_384;
extern t_pbkdf2_prf	g_prf_hmac_sha_512;
extern t_pbkdf2_prf	g_prf_hmac_sha_512_224;
extern t_pbkdf2_prf	g_prf_hmac_sha_512_256;

static t_pbkdf2_prf*	select_prf(const char* algo_name) {
	if (ft_strcmp(algo_name, "md5") == 0) { return &g_prf_hmac_md5; }
	if (ft_strcmp(algo_name, "sha224") == 0) { return &g_prf_hmac_sha_224; }
	if (ft_strcmp(algo_name, "sha256") == 0) { return &g_prf_hmac_sha_256; }
	if (ft_strcmp(algo_name, "sha384") == 0) { return &g_prf_hmac_sha_384; }
	if (ft_strcmp(algo_name, "sha512") == 0) { return &g_prf_hmac_sha_512; }
	if (ft_strcmp(algo_name, "sha512-224") == 0) { return &g_prf_hmac_sha_512_224; }
	if (ft_strcmp(algo_name, "sha512-256") == 0) { return &g_prf_hmac_sha_512_256; }
	return NULL;
}

// -a は名前から疑似乱数関数の実体を引くので, 表に書ける代入では済まない
static bool	set_pbkdf2_prf(const t_master* master, void* pref, const char* value) {
	t_pbkdf2_prf*	prf = select_prf(value);
	if (prf == NULL) {
		print_error_by_message(master, "unexpected PRF name");
		return false;
	}
	((t_preference_pbkdf2*)pref)->prf = prf;
	return true;
}

// `pbkdf2` のオプション.
// -c (ストレッチ回数) の格納先は uint32_t, -l (導出鍵長) は uint64_t なので kind を分ける.
static const t_option_spec	g_options_pbkdf2[] = {
	{ .name = "a", .kind = OPTION_CUSTOM, .handle = set_pbkdf2_prf },
	{ .name = "s", .kind = OPTION_STRING, .field_offset = offsetof(t_preference_pbkdf2, path_salt) },
	{ .name = "S", .kind = OPTION_STRING, .field_offset = offsetof(t_preference_pbkdf2, message_argument) },
	{ .name = "c", .kind = OPTION_UINT32, .field_offset = offsetof(t_preference_pbkdf2, stretch),
	  .min = 1, .max = UINT32_MAX },
	{ .name = "l", .kind = OPTION_UINT64, .field_offset = offsetof(t_preference_pbkdf2, dklen),
	  .min = 1, .max = UINT32_MAX },
	{ .name = NULL },
};

int	parse_options_pbkdf2(const t_master* master, char** argv, t_preference_pbkdf2* pref_ptr) {
	t_preference_pbkdf2	pref = {
		.stretch = 1,
		.dklen = 20,
	};
	const int	parsed_count = parse_options(master, argv, &pref, g_options_pbkdf2);
	if (parsed_count < 0) {
		return -1;
	}
	if (pref.prf == NULL) {
		// set default
		pref.prf = &g_prf_hmac_sha_256;
	}
	*pref_ptr = pref;
	return parsed_count;
}
