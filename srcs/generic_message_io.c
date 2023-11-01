#include "ft_ssl.h"

static void	message_to_gm(t_generic_message* gm, const t_message* msg) {
	*gm = (t_generic_message) {
		.message = msg->message,
		.byte_size = msg->message_bit_len / OCTET_BIT_SIZE,
	};
}

t_generic_message	new_generic_message_path(t_master* master, const char* path) {
	t_generic_message	gm = {};
	t_message	message = {};
	if (create_message_path(master, &message, path)) {
		message_to_gm(&gm, &message);
	} else {
		mark_faild_generic_message(&gm);
	}
	return gm;
}

t_generic_message	new_generic_message_stdin(t_master* master) {
	t_generic_message	gm = {};
	t_message	message = {};
	if (create_message_stdin(master, &message)) {
		message_to_gm(&gm, &message);
	} else {
		mark_faild_generic_message(&gm);
	}
	return gm;
}

t_generic_message	new_generic_message_str(t_master* master, const char* str) {
	(void)master;
	char*	str_copy = ft_strdup(str);
	if (str_copy == NULL) {
		return FAILED_GENERIC_MESSAGE;
	}
	return (t_generic_message){
		.byte_size = ft_strlen(str_copy),
		.message = str_copy,
	};
}
