#ifndef FT_SSL_HMAC_H
#define FT_SSL_HMAC_H

#include "ft_ssl_structure.h"

void	generic_digest_md5(t_generic_message* result, const t_generic_message *message);
void	generic_digest_sha_224(t_generic_message* result, const t_generic_message *text);
void	generic_digest_sha_256(t_generic_message* result, const t_generic_message *text);
void	generic_digest_sha_384(t_generic_message* result, const t_generic_message *text);
void	generic_digest_sha_512(t_generic_message* result, const t_generic_message *text);
void	generic_digest_sha_512_224(t_generic_message* result, const t_generic_message *text);
void	generic_digest_sha_512_256(t_generic_message* result, const t_generic_message *text);

t_generic_message hmac_md5(const t_generic_message *key, const t_generic_message *text);
t_generic_message hmac_sha_224(const t_generic_message *key, const t_generic_message *text);
t_generic_message hmac_sha_256(const t_generic_message *key, const t_generic_message *text);
t_generic_message hmac_sha_384(const t_generic_message *key, const t_generic_message *text);
t_generic_message hmac_sha_512(const t_generic_message *key, const t_generic_message *text);
t_generic_message hmac_sha_512_224(const t_generic_message *key, const t_generic_message *text);
t_generic_message hmac_sha_512_256(const t_generic_message *key, const t_generic_message *text);

t_hmac_hash_interface	x_make_hmac_interface(const t_hash_algorithm* algorithm);

t_generic_message	hmac(
	const t_hmac_hash_interface* hi,
	const t_generic_message* key,
	const t_generic_message* text
);

int	parse_options_hmac(const t_master* master, char** argv, t_preference* pref_ptr);
t_generic_message	new_generic_message_path(t_master* master, const char* path);
t_generic_message	new_generic_message_stdin(t_master* master);

int	run_hmac(t_master* master, char **argv);

#endif
