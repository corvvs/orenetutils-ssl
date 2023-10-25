#include "ft_ssl.h"
#include "ft_ssl_preference.h"

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

int	parse_options_hmac(const t_master* master, char** argv, t_preference* pref_ptr) {
	(void)master;
	t_preference	pref = {};
	int parsed_count = 0;
	while (*argv != NULL && ft_strncmp(*argv, "-", 1) == 0) {

		const char*	option = *argv;
		++option;
		while (*option) {
			switch (*option) {
				case 'a': {
					/* option に後続がある場合はアウト */
					if (option[1]) {
						print_error_by_message(master, "illegal option -- a\n");
						return -1;
					}
					/* argv に後続がない場合はアウト */
					argv += 1;
					if (*argv == NULL) {
						print_error_by_message(master, "option requires an argument -- a\n");
						return -1;
					}

					t_hmac_hash_interface*	hi = select_hi(*argv);
					if (hi == NULL) {
						print_error_by_message(master, "unexpected hash algorithm name\n");
						return -1;
					}
					pref.hi = hi;
					parsed_count += 1;
					break;
				}
				PARSE_PREFERENCE_WITH_1_ARGUMENT('k', k, path_key)
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
	if (pref.hi == NULL) {
		// set default
		pref.hi = &g_hi_sha_256;
	}
	*pref_ptr = pref;
	return parsed_count;
}

