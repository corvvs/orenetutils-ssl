#include "ft_ssl.h"

extern t_hmac_hash_interface	g_hi_md5;
extern t_hmac_hash_interface	g_hi_sha_224;
extern t_hmac_hash_interface	g_hi_sha_256;
extern t_hmac_hash_interface	g_hi_sha_384;
extern t_hmac_hash_interface	g_hi_sha_512;
extern t_hmac_hash_interface	g_hi_sha_512_224;
extern t_hmac_hash_interface	g_hi_sha_512_256;

#define define_hmac_frontend(hash_type)                                                             \
	t_generic_message hmac_##hash_type(const t_generic_message *key, const t_generic_message *text) \
	{                                                                                               \
		return hmac(&g_hi_##hash_type, key, text);                                                  \
	}

define_hmac_frontend(md5)
define_hmac_frontend(sha_224)
define_hmac_frontend(sha_256)
define_hmac_frontend(sha_384)
define_hmac_frontend(sha_512)
define_hmac_frontend(sha_512_224)
define_hmac_frontend(sha_512_256)
