#include "generic_message.h"
#include "libft.h"
#include <assert.h>

bool	is_failed_generic_message(const t_generic_message* message) {
	return message->is_failed;
}

void	mark_faild_generic_message(t_generic_message* message) {
	message->is_failed = true;
}

t_generic_message	new_generic_message(size_t byte_size) {
	if (byte_size == 0) {
		return (t_generic_message){
			.byte_size = 0,
			.message = NULL,
		};
	}
	void*	data = malloc(byte_size);
	if (data == NULL) {
		return FAILED_GENERIC_MESSAGE;
	}
	return (t_generic_message) {
		.message = data,
		.byte_size = byte_size,
	};
}

void	copy_generic_message(t_generic_message* dest, const t_generic_message* src) {
	assert(dest->byte_size >= src->byte_size);
	ft_memmove(dest->message, src->message, src->byte_size);
}

t_generic_message	dup_generic_message(const t_generic_message* src) {
	void*	duplicated = ft_memdup(src->message, src->byte_size);
	if (duplicated == NULL) {
		return FAILED_GENERIC_MESSAGE;
	}
	return (t_generic_message){
		.message = duplicated,
		.byte_size = src->byte_size,
	};
}

// データ連結を行う: a = a + b
bool	join_assign_generic_message(t_generic_message* a, const t_generic_message* b) {
	size_t	joined_size = a->byte_size + b->byte_size;
	void*	joined = malloc(joined_size);
	if (joined == NULL) {
		return false;
	}
	ft_memmove(joined, a->message, a->byte_size);
	ft_memmove(joined + a->byte_size, b->message, b->byte_size);
	free(a->message);
	*a = (t_generic_message){
		.message = joined,
		.byte_size = joined_size,
	};
	return true;
}

// ビットワイズXORを行う: a = a ^ b
void	xor_assign_generic_message(t_generic_message* a, const t_generic_message* b) {
	if (is_failed_generic_message(a) || is_failed_generic_message(b)) {
		return;
	}
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

void	print_generic_message_hex(const t_generic_message* message, int fd) {
	// dprintf(fd, "byte_size: %zu, \t", message->byte_size);
	// dprintf(fd, "data: ");
	for (size_t i = 0; i < message->byte_size; ++i) {
		dprintf(fd, "%02x", ((uint8_t*)message->message)[i]);
	}
	// write(fd, "\n", 1);
}

void	print_generic_message_ascii(const t_generic_message* message, int fd) {
	// dprintf(fd, "byte_size: %zu, \t", message->byte_size);
	// dprintf(fd, "data: \"");
	write(fd, message->message, message->byte_size);
	// write(fd, "\"\n", 2);
}
