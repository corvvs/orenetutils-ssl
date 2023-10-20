#include "ft_ssl.h"

// extern t_hmac_hash_interface	g_hi_md5;
// extern t_hmac_hash_interface	g_hi_sha_224;
extern t_hmac_hash_interface	g_hi_sha_256;
// extern t_hmac_hash_interface	g_hi_sha_384;
// extern t_hmac_hash_interface	g_hi_sha_512;
// extern t_hmac_hash_interface	g_hi_sha_512_224;
// extern t_hmac_hash_interface	g_hi_sha_512_256;

int	run_test(t_master* master, char **argv) {
	(void)master;
	(void)argv;

	const t_generic_message key = {
		.message = "Jefe",
		.byte_size = 4,
	};
	const t_generic_message plain = {
		.message = "what do ya want for nothing?",
		.byte_size = 28,
	};

	const t_hmac_hash_interface* hi = &g_hi_sha_256;
	t_generic_message mac = hmac(hi, &key, &plain);
	yoyo_dprintf(STDOUT_FILENO, "hash algorithm: \t%s\n", hi->name);
	yoyo_dprintf(STDOUT_FILENO, "key: \t");
	print_generic_message_ascii(&key, STDOUT_FILENO);
	yoyo_dprintf(STDOUT_FILENO, "text: \t");
	print_generic_message_ascii(&plain, STDOUT_FILENO);
	yoyo_dprintf(STDOUT_FILENO, "HMAC: \t");
	print_generic_message(&mac, STDOUT_FILENO);


	return 1;
}
