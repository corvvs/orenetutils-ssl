#ifndef FT_SSL_H
#define FT_SSL_H

#include "ft_ssl_md5.h"
#include "utils_endian.h"
#include "ft_ssl_structure.h"

typedef enum e_command {
	COMMAND_MD5,
	COMMAND_SHA256,
	COMMAND_UNKNOWN
}	t_command;

typedef struct e_command_pair {
	const char* name;
	t_command	algo;
}	t_command_pair;

#define DEF_COMMAND_PAIR(n, a) (t_command_pair){ .name = n, .algo = a }

static const t_command_pair g_command_pairs[] = {
	DEF_COMMAND_PAIR("md5", COMMAND_MD5),
	DEF_COMMAND_PAIR("sha256", COMMAND_SHA256),
};

// md5.c
void digest_md5(const uint8_t *message, size_t bit_len);

// sha_256.c
void digest_sha_2(const uint8_t *message, size_t bit_len);

// read_file.c
bool	read_file(int ifd, t_elastic_buffer* buffer_ptr);

// utils_endian.h
bool is_little_endian(void);

#endif