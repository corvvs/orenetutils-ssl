#include "ft_ssl.h"

t_hmac_hash_interface	g_hi_md5;
t_hmac_hash_interface	g_hi_sha_224;
t_hmac_hash_interface	g_hi_sha_256;
t_hmac_hash_interface	g_hi_sha_384;
t_hmac_hash_interface	g_hi_sha_512;
t_hmac_hash_interface	g_hi_sha_512_224;
t_hmac_hash_interface	g_hi_sha_512_256;

t_pbkdf2_prf			g_prf_hmac_md5;
t_pbkdf2_prf			g_prf_hmac_sha_224;
t_pbkdf2_prf			g_prf_hmac_sha_256;
t_pbkdf2_prf			g_prf_hmac_sha_384;
t_pbkdf2_prf			g_prf_hmac_sha_512;
t_pbkdf2_prf			g_prf_hmac_sha_512_224;
t_pbkdf2_prf			g_prf_hmac_sha_512_256;

bool	on_startup(void) {
	// HMAC - Hash インターフェースの作成
	g_hi_md5         = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_md5);
	g_hi_sha_224     = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_224);
	g_hi_sha_256     = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_256);
	g_hi_sha_384     = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_384);
	g_hi_sha_512     = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_512);
	g_hi_sha_512_224 = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_512_224);
	g_hi_sha_512_256 = (t_hmac_hash_interface)x_make_hmac_interface(&g_hash_sha_512_256);

	// PRF(PBKDF2 - HMAC) インターフェースの作成
	g_prf_hmac_md5         = (t_pbkdf2_prf)make_prf(hmac_md5, &g_hi_md5);
	g_prf_hmac_sha_224     = (t_pbkdf2_prf)make_prf(hmac_sha_224, &g_hi_sha_224);
	g_prf_hmac_sha_256     = (t_pbkdf2_prf)make_prf(hmac_sha_256, &g_hi_sha_256);
	g_prf_hmac_sha_384     = (t_pbkdf2_prf)make_prf(hmac_sha_384, &g_hi_sha_384);
	g_prf_hmac_sha_512     = (t_pbkdf2_prf)make_prf(hmac_sha_512, &g_hi_sha_512);
	g_prf_hmac_sha_512_224 = (t_pbkdf2_prf)make_prf(hmac_sha_512_224, &g_hi_sha_512_224);
	g_prf_hmac_sha_512_256 = (t_pbkdf2_prf)make_prf(hmac_sha_512_256, &g_hi_sha_512_256);
	return true;
}
