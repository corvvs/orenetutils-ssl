#include "generic_message.h"
#include "libft.h"
#include <assert.h>

t_generic_message	new_generic_message(size_t byte_size) {
	void*	data = malloc(byte_size);
	return (t_generic_message) {
		.message = data,
		.byte_size = data != NULL
			? byte_size
			: 0,
	};
}

void	copy_generic_message(t_generic_message* dest, const t_generic_message* src) {
	assert(dest->byte_size >= src->byte_size);
	ft_memmove(dest->message, src->message, src->byte_size);
}

t_generic_message	dup_generic_message(const t_generic_message* src) {
	void*	duplicated = ft_memdup(src->message, src->byte_size);
	return (t_generic_message){
		.message = duplicated,
		.byte_size = duplicated != NULL
			? src->byte_size
			: 0,
	};
}

// データ連結を行う: a = a + b
void	join_assign_generic_message(t_generic_message* a, const t_generic_message* b) {
	size_t	joined_size = a->byte_size + b->byte_size;
	void*	joined = malloc(joined_size);
	if (joined == NULL) {
		joined_size = 0;
	} else {
		ft_memmove(joined, a->message, a->byte_size);
		ft_memmove(joined + a->byte_size, b->message, b->byte_size);
	}
	free(a->message);
	*a = (t_generic_message){
		.message = joined,
		.byte_size = joined_size,
	};
}

// ビットワイズXORを行う: a = a ^ b
void	xor_assign_generic_message(t_generic_message* a, const t_generic_message* b) {
	assert(a->byte_size == b->byte_size);
	uint8_t*		va = a->message;
	const uint8_t*	vb = b->message;
	for (size_t i = 0; i < a->byte_size; ++i) {
		va[i] = va[i] ^ vb[i];
	}
}

void	destroy_generic_message(t_generic_message* message) {
	free(message->message);
	message->message = NULL;
	message->byte_size = 0;
}

void	print_generic_message(const t_generic_message* message, int fd) {
	dprintf(fd, "byte_size: %zu, \t", message->byte_size);
	dprintf(fd, "data: ");
	for (size_t i = 0; i < message->byte_size; ++i) {
		dprintf(fd, "%02x", ((uint8_t*)message->message)[i]);
	}
	write(fd, "\n", 1);
}

void	print_generic_message_ascii(const t_generic_message* message, int fd) {
	dprintf(fd, "byte_size: %zu, \t", message->byte_size);
	dprintf(fd, "data: \"");
	write(fd, message->message, message->byte_size);
	write(fd, "\"\n", 2);
}
