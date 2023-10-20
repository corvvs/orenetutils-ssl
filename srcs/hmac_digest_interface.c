#include "ft_ssl.h"

// static t_generic_message	convert_to_digest(const void* data, size_t data_len) {
// 	return dup_generic_message(&(t_generic_message){
// 		.message = (void*)data,
// 		.byte_size = data_len,
// 	});
// }

#define define_generic_digest(hash_type)                                                      \
	void generic_digest_##hash_type(t_generic_message *result, const t_generic_message *text) \
	{                                                                                         \
		const size_t message_bit_size = text->byte_size * OCTET_BIT_SIZE;                     \
		t_##hash_type##_digest d = hash_type##_hash(text->message, message_bit_size);         \
		ft_memmove(result->message, d.digest, sizeof(d.digest));                              \
		result->byte_size = sizeof(d.digest);                                                 \
	}

define_generic_digest(md5)
define_generic_digest(sha_224)
define_generic_digest(sha_256)
define_generic_digest(sha_384)
define_generic_digest(sha_512)
define_generic_digest(sha_512_224)
define_generic_digest(sha_512_256)

// 失敗時 exit(1) する
t_hmac_hash_interface	x_make_hmac_interface(const t_hash_algorithm* algorithm) {
	size_t	pad_size = algorithm->block_byte_size;
	void*	ipad = malloc(pad_size);
	void*	opad = malloc(pad_size);
	if (ipad == NULL || opad == NULL) {
		free(ipad);
		free(opad);
		exit(1);
	} else {
		ft_memset(ipad, 0x36, pad_size);
		ft_memset(opad, 0x5c, pad_size);
	}
	return (t_hmac_hash_interface) {
		.name = algorithm->name,
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
