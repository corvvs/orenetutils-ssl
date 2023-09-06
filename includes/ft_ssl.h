#ifndef FT_SSL_H
#define FT_SSL_H

#include "ft_ssl_md5.h"
#include "utils_endian.h"
#include "ft_ssl_structure.h"
#include "ft_ssl_lib.h"

typedef enum e_command {
	COMMAND_MD5,
	COMMAND_SHA224,
	COMMAND_SHA256,
	COMMAND_SHA512,
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
	DEF_COMMAND_PAIR("sha512", COMMAND_SHA512),
};

typedef struct s_master {
	const char*		program_name;
	t_command		command;
	const char*		command_name;
	t_preference	pref;
}	t_master;


// md5.c
void digest_md5(const t_preference* pref, const t_message* message);

// sha_224.c
void digest_sha_224(const t_preference* pref, const t_message* message);

// sha_256.c
void digest_sha_256(const t_preference* pref, const t_message* message);

// sha_512.c
void digest_sha_512(const t_preference* pref, const t_message* message);

// preference.c
int	parse_options(const t_master* master, char** argv, t_preference* pref_ptr);

// read_file.c
bool	read_file(const t_master* master, int ifd, t_elastic_buffer* buffer_ptr);

// run_command.c
int	run_command(const t_master* master, char **argv);

// utils_endian.c
bool is_little_endian(void);

// utils_error.c
void print_error_by_message(const t_master* master, const char* message);
void print_error_by_errno(const t_master* master);

// utils_print.c
void put_bytestream(int fd, const uint8_t* data, size_t len);

#endif
