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

typedef enum e_command {
	COMMAND_MD5,
	COMMAND_SHA224,
	COMMAND_SHA256,
	COMMAND_SHA384,
	COMMAND_SHA512,
	COMMAND_SHA512_224,
	COMMAND_SHA512_256,
	COMMAND_UNKNOWN
}	t_command;

typedef void (t_digest_func)(const t_preference*, const t_message*);

typedef struct e_command_pair {
	const char* 	name;
	t_digest_func*	func;
}	t_command_pair;

#define DEF_COMMAND_PAIR(n, f) (t_command_pair){ .name = n, .func = f }

typedef struct s_master {
	const char*		program_name;
	t_command_pair	command;
	const char*		command_name;
}	t_master;

typedef struct s_master_digest {
	t_master			master;
	t_preference	pref;
}	t_master_digest;

#endif
