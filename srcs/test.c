#include "ft_ssl.h"

int	run_test(t_master* master, char **argv) {
	(void)master;
	(void)argv;

	t_hash_algorithm	algorithm = {
		.func = generic_digest_md5,
		.block_byte_size = MD5_WORD_BLOCK_BIT_SIZE / OCTET_BIT_SIZE	,
		.hash_byte_size = MD5_DIGEST_BIT_SIZE / OCTET_BIT_SIZE,
	};
	t_hmac_hash_interface hi = make_hmac_interface(&algorithm);
	t_generic_message mac = hmac(&hi, &(t_generic_message){
		.message = "Jefe",
		.byte_size = 4,
	}, &(t_generic_message){
		.message = "what do ya want for nothing?",
		.byte_size = 28,
	});
	DEBUGOUT("mac: %zu\n", mac.byte_size);
	write(STDOUT_FILENO, mac.message, mac.byte_size);
	write(STDOUT_FILENO, "\n", 1);
	return 1;
}
