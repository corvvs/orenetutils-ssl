#ifndef FT_SSL_PBKDF2_H
#define FT_SSL_PBKDF2_H

#include "ft_ssl_structure.h"

t_generic_message	pbkdf2(
	const t_pbkdf2_prf* prf,
	const t_generic_message* password,
	const t_generic_message* salt,
	size_t c,
	size_t dklen
);

t_pbkdf2_prf	make_prf(hmac_function* hmac, const t_hmac_hash_interface* hi);

int	parse_options_pbkdf2(const t_master* master, char** argv, t_preference* pref_ptr);
int	run_pbkdf2(t_master* master, char **argv);

#endif
