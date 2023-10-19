#include "ft_ssl.h"

// static t_generic_message	convert_to_digest(const void* data, size_t data_len) {
// 	return dup_generic_message(&(t_generic_message){
// 		.message = (void*)data,
// 		.byte_size = data_len,
// 	});
// }

void	generic_digest_md5(t_generic_message* result, const t_generic_message *text) {
	const size_t message_bit_size = text->byte_size * OCTET_BIT_SIZE;
	t_md5_digest d = md5_hash(text->message, message_bit_size);
	ft_memmove(result->message, d.digest, sizeof(d.digest));
	result->byte_size = sizeof(d.digest);
}

void	generic_digest_sha256(t_generic_message* result, const t_generic_message *text) {
	const size_t message_bit_size = text->byte_size * OCTET_BIT_SIZE;
	t_sha_256_digest d = sha_256_hash(text->message, message_bit_size);
	ft_memmove(result->message, d.digest, sizeof(d.digest));
	result->byte_size = sizeof(d.digest);
}

t_hmac_hash_interface	make_hmac_interface(const t_hash_algorithm* algorithm) {
	size_t	pad_size = algorithm->block_byte_size;
	void*	ipad = malloc(pad_size);
	void*	opad = malloc(pad_size);
	if (ipad == NULL || opad == NULL) {
		free(ipad);
		free(opad);
		ipad = NULL;
		opad = NULL;
		pad_size = 0;
	} else {
		ft_memset(ipad, 0x36, pad_size);
		ft_memset(opad, 0x5c, pad_size);
	}
	return (t_hmac_hash_interface) {
		.algorithm = *algorithm,
		.ipad = (t_generic_message){
			.message = ipad,
			.byte_size = pad_size,
		},
		.opad = (t_generic_message){
			.message = opad,
			.byte_size = pad_size,
		},
	};
}
