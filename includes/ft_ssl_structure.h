#ifndef FT_SSL_STRUCTURE_H
#define FT_SSL_STRUCTURE_H

#include "common.h"

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

typedef struct e_command_pair {
	const char* name;
	t_command	algo;
}	t_command_pair;

#define DEF_COMMAND_PAIR(n, a) (t_command_pair){ .name = n, .algo = a }

static const t_command_pair g_command_pairs[] = {
	DEF_COMMAND_PAIR("md5", COMMAND_MD5),
	DEF_COMMAND_PAIR("sha224", COMMAND_SHA224),
	DEF_COMMAND_PAIR("sha256", COMMAND_SHA256),
	DEF_COMMAND_PAIR("sha384", COMMAND_SHA384),
	DEF_COMMAND_PAIR("sha512", COMMAND_SHA512),
	DEF_COMMAND_PAIR("sha512-224", COMMAND_SHA512_224),
	DEF_COMMAND_PAIR("sha512-256", COMMAND_SHA512_256),
};

typedef struct s_message
{
	bool is_bytestream;
	const char *file_path; // これが NULL かつ is_bytestream が true のときは stdin とみなす
	u_int8_t *message;
	size_t message_bit_len;
} t_message;

typedef struct s_preference_digest {
	bool	is_echo;			// -p option
	bool	is_quiet;			// -q option
	bool	is_reverse;			// -r option
	char*	message_argument;	// -s option
}	t_preference_digest;

typedef struct s_master {
	const char*		program_name;
	t_command		command;
	const char*		command_name;
}	t_master;

typedef struct s_master_digest {
	t_master			master;
	t_preference_digest	pref;
}	t_master_digest;

#endif
