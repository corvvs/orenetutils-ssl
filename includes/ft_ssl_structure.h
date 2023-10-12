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

	bool	is_decode;
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

struct s_master;

typedef int (t_runner_func)(struct s_master *master, char **);

typedef struct e_command_pair {
	const char* 	name;
	t_runner_func*	func;
}	t_command_pair;

#define DEF_COMMAND_PAIR(n, f) (t_command_pair){ .name = n, .func = f }

typedef struct s_master {
	const char*		program_name;
	t_command_pair	command;
	const char*		command_name;

	bool				in_repl;
	t_elastic_buffer	repl;
	bool				stdin_eof_reached;
}	t_master;

typedef struct s_master_digest {
	t_master		master;
	t_preference	pref;
}	t_master_digest;

typedef struct s_master_base64 {
	t_master		master;
	t_preference	pref;
}	t_master_base64;

#endif
