#include "ft_ssl.h"



int main(int argc, char **argv) {
	if (argc < 2) {
		printf("usage: ft_ssl command [command opts] [command args]\n");
		return (0);
	}
	const char*	arg = argv[1];
	size_t		arg_len = ft_strlen(arg);
	t_md5_digest digest =  md5_hash((const uint8_t*)arg, arg_len * 8);
	printf("digest:\n");
	for (size_t i = 0; i < sizeof(digest.digest) / sizeof(uint8_t); i++) {
		printf("%02x", digest.digest[i]);
	}
	printf("\n");
}
