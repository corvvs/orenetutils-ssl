#ifndef FT_SSL_STRUCTURE_H
#define FT_SSL_STRUCTURE_H

#include "common.h"

typedef struct s_message
{
	bool is_file;
	const char *file_path; // これが NULL かつ is_file が true のときは stdin とみなす
	u_int8_t *message;
	size_t message_bit_len;
} t_message;

#endif
