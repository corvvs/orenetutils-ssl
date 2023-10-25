#ifndef GENERIC_MESSAGE_H
#define GENERIC_MESSAGE_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

typedef struct s_generic_message {
	void*	message;
	size_t	byte_size;
	bool	is_failed;
}	t_generic_message;

bool				is_failed_generic_message(const t_generic_message* message);
void				mark_faild_generic_message(t_generic_message* message);
t_generic_message	new_generic_message(size_t byte_size);
void				copy_generic_message(t_generic_message* dest, const t_generic_message* src);
t_generic_message	dup_generic_message(const t_generic_message* src);
bool				join_assign_generic_message(t_generic_message* a, const t_generic_message* b);
void				xor_assign_generic_message(t_generic_message* a, const t_generic_message* b);
void				destroy_generic_message(t_generic_message* message);
void				print_generic_message_hex(const t_generic_message* message, int fd);
void				print_generic_message_ascii(const t_generic_message* message, int fd);

#endif
