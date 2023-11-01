#include "ft_ssl.h"
#include "ft_ssl_preference.h"

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

int	parse_options_pbkdf2(const t_master* master, char** argv, t_preference* pref_ptr) {
	(void)master;
	t_preference	pref = {
		.stretch = 1,
		.dklen = 20,
	};
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

					t_pbkdf2_prf*	prf = select_prf(*argv);
					if (prf == NULL) {
						print_error_by_message(master, "unexpected PRF name\n");
						return -1;
					}
					pref.prf = prf;
					parsed_count += 1;
					break;
				}
				PARSE_PREFERENCE_WITH_1_ARGUMENT('s', s, path_salt)
				PARSE_PREFERENCE_WITH_1_ARGUMENT('S', S, message_argument)
				case 'c': {
					/* option に後続がある場合はアウト */
					if (option[1]) {
						print_error_by_message(master, "illegal option -- c\n");
						return -1;
					}
					/* argv に後続がない場合はアウト */
					argv += 1;
					if (*argv == NULL) {
						print_error_by_message(master, "option requires an argument -- c\n");
						return -1;
					}
					uint64_t	stretch;
					if (parse_uint64(master, *argv, &stretch, 1, UINT32_MAX)) {
						print_error_by_message(master, "invalid stretch count\n");
						return -1;
					}
					pref.stretch = stretch;
					parsed_count += 1;
					break;
				}
				case 'l': {
					/* option に後続がある場合はアウト */
					if (option[1]) {
						print_error_by_message(master, "illegal option -- l\n");
						return -1;
					}
					/* argv に後続がない場合はアウト */
					argv += 1;
					if (*argv == NULL) {
						print_error_by_message(master, "option requires an argument -- l\n");
						return -1;
					}
					uint64_t	dklen;
					if (parse_uint64(master, *argv, &dklen, 1, UINT32_MAX)) {
						print_error_by_message(master, "invalid dklen\n");
						return -1;
					}
					pref.dklen = dklen;
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
	if (pref.prf == NULL) {
		// set default
		pref.prf = &g_prf_hmac_sha_256;
	}
	*pref_ptr = pref;
	return parsed_count;
}

