#ifndef FT_SSL_H
#define FT_SSL_H

#include "ft_ssl_md5.h"
#include "utils_endian.h"
#include "ft_ssl_structure.h"
#include "ft_ssl_lib.h"

// md5.c
int run_md5(const t_master *master, char **argv);

// sha_***.c
int run_sha_224(const t_master *master, char **argv);
int run_sha_256(const t_master *master, char **argv);
int run_sha_384(const t_master *master, char **argv);
int run_sha_512(const t_master *master, char **argv);
int run_sha_512_224(const t_master *master, char **argv);
int run_sha_512_256(const t_master *master, char **argv);

// preference.c
int	parse_options_digest(const t_master* master, char** argv, t_preference* pref_ptr);

// read_file.c
bool	read_file(const t_master* master, int ifd, t_elastic_buffer* buffer_ptr);

// run_command.c
int	run_command(const t_master* master, char **argv);

// run_digest_helper.c
bool	create_message_stdin(const t_master* master, t_message* message_ptr);
bool	create_message_argument(const t_master* master, t_message* message_ptr, char *arg);
bool	create_message_path(const t_master* master, t_message* message_ptr, const char* path);
void	destroy_message(t_message* message);

// utils_endian.c
bool is_little_endian(void);

// utils_error.c
void print_error_by_message(const t_master* master, const char* message);

// utils_print.c
void put_bitstream(int fd, const uint8_t* data, size_t bit_len);

#define PRINT_ERROR(master, format, ...) yoyo_dprintf(STDERR_FILENO, "%s: %s: " format, (master)->program_name, (master)->command_name, __VA_ARGS__)

static const t_command_pair g_command_pairs[] = {
	DEF_COMMAND_PAIR("md5", run_md5),
	DEF_COMMAND_PAIR("sha224", run_sha_224),
	DEF_COMMAND_PAIR("sha256", run_sha_256),
	DEF_COMMAND_PAIR("sha384", run_sha_384),
	DEF_COMMAND_PAIR("sha512", run_sha_512),
	DEF_COMMAND_PAIR("sha512-224", run_sha_512_224),
	DEF_COMMAND_PAIR("sha512-256", run_sha_512_256),
	DEF_COMMAND_PAIR(NULL, NULL),
};

#endif
