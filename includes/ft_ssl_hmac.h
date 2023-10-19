#ifndef FT_SSL_HMAC_H
#define FT_SSL_HMAC_H

#include "ft_ssl_structure.h"
#include "generic_message.h"

typedef	void	(generic_hash_function)(t_generic_message* result, const t_generic_message* text);

typedef struct s_hash_algorithm {
	generic_hash_function*	func;
	size_t					block_byte_size;
	size_t					hash_byte_size;
}	t_hash_algorithm;

typedef struct s_hmac_hash_interface {
	t_hash_algorithm	algorithm;
	t_generic_message	ipad;
	t_generic_message	opad;
}	t_hmac_hash_interface;

void	generic_digest_md5(t_generic_message* result, const t_generic_message *message);
void	generic_digest_sha256(t_generic_message* result, const t_generic_message *text);

t_hmac_hash_interface	make_hmac_interface(const t_hash_algorithm* algorithm);

t_generic_message	hmac(
	const t_hmac_hash_interface* hi,
	const t_generic_message* key,
	const t_generic_message* text
);

#endif
