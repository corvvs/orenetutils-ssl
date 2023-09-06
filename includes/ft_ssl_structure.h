#ifndef FT_SSL_STRUCTURE_H
#define FT_SSL_STRUCTURE_H

#include "common.h"

typedef struct s_message
{
	bool is_bytestream;
	const char *file_path; // これが NULL かつ is_bytestream が true のときは stdin とみなす
	u_int8_t *message;
	size_t message_bit_len;
} t_message;

typedef struct s_preference {
	bool	is_echo;			// -p option
	bool	is_quiet;			// -q option
	bool	is_reverse;			// -r option
	char*	message_argument;	// -s option
}	t_preference;

#endif
