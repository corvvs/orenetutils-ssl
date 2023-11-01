#include "ft_ssl.h"
#include "generic_message.h"

// HMACをPBKDF2のPRFとして使うためのヘルパー群

t_pbkdf2_prf	make_prf(hmac_function* hmac, const t_hmac_hash_interface* hi) {
	return (t_pbkdf2_prf) {
		.name = hi->algorithm.name,
		.func = hmac,
		.hlen = hi->algorithm.hash_byte_size,
	};
}
