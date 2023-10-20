#ifndef FT_SSL_H
#define FT_SSL_H

#include "ft_ssl_md5.h"
#include "ft_ssl_sha_2.h"
#include "utils_endian.h"
#include "ft_ssl_structure.h"
#include "ft_ssl_lib.h"
#include "ft_ssl_hmac.h"

#define READ_BUFFER_SIZE (128 << 10)

int run_help(t_master *master, char **argv);

// md5.c
int run_md5(t_master *master, char **argv);

// sha_***.c
int run_sha_224(t_master *master, char **argv);
int run_sha_256(t_master *master, char **argv);
int run_sha_384(t_master *master, char **argv);
int run_sha_512(t_master *master, char **argv);
int run_sha_512_224(t_master *master, char **argv);
int run_sha_512_256(t_master *master, char **argv);

// base64
int	base64_encode(t_master_base64* m, t_elastic_buffer* input, int out_fd);
int	base64_decode(t_master_base64* m, t_elastic_buffer* input, int out_fd);
int	run_base64(t_master* master, char **argv);

int	run_test(t_master* master, char **argv);

// digest core
t_md5_digest			md5_hash(const uint8_t *message, uint64_t message_len);
t_sha_224_digest		sha_224_hash(const uint8_t *message, uint64_t message_len);
t_sha_256_digest		sha_256_hash(const uint8_t *message, uint64_t message_len);
t_sha_384_digest		sha_384_hash(const uint8_t *message, uint64_t message_len);
t_sha_512_digest		sha_512_hash(const uint8_t *message, uint64_t message_len);
t_sha_512_224_digest	sha_512_224_hash(const uint8_t *message, uint64_t message_len);
t_sha_512_256_digest	sha_512_256_hash(const uint8_t *message, uint64_t message_len);

// repl.c
int run_in_repl(t_master* master);

// preference.c
int	parse_options_digest(const t_master* master, char** argv, t_preference* pref_ptr);

// base64_preference.c
int	parse_options_base64(const t_master* master, char** argv, t_preference* pref_ptr);

// read_file.c
bool	read_file(t_master* master, int ifd, t_elastic_buffer* joined);

// run_command.c
int		run_command(t_master* master, const char* command_name, char** const arguments);

// run_digest_helper.c
bool	create_message_stdin(t_master* master, t_message* message_ptr);
bool	create_message_argument(const t_master* master, t_message* message_ptr, char *arg);
bool	create_message_path(t_master* master, t_message* message_ptr, const char* path);
void	destroy_message(t_message* message);

// elastic_buffer_helper.c
bool	create_buffer_stdin(t_master* master, t_elastic_buffer* message_ptr);
bool	create_buffer_path(t_master* master, t_elastic_buffer* message_ptr, const char* path);
void	destroy_buffer(t_elastic_buffer* message);

// utils_endian.c
bool is_little_endian(void);

// utils_error.c
void print_error_by_message(const t_master* master, const char* message);

// utils_print.c
void put_bitstream(int fd, const uint8_t* data, size_t bit_len);

#define PRINT_ERROR(master, format, ...) yoyo_dprintf(STDERR_FILENO, "%s: %s: " format, (master)->program_name, (master)->command_name, __VA_ARGS__)

static const t_command_pair g_command_pairs[] = {
	DEF_COMMAND_PAIR("help", run_help),
	DEF_COMMAND_PAIR("md5", run_md5),
	DEF_COMMAND_PAIR("sha224", run_sha_224),
	DEF_COMMAND_PAIR("sha256", run_sha_256),
	DEF_COMMAND_PAIR("sha384", run_sha_384),
	DEF_COMMAND_PAIR("sha512", run_sha_512),
	DEF_COMMAND_PAIR("sha512-224", run_sha_512_224),
	DEF_COMMAND_PAIR("sha512-256", run_sha_512_256),
	DEF_COMMAND_PAIR("base64", run_base64),
	DEF_COMMAND_PAIR("test", run_test),

	DEF_COMMAND_PAIR(NULL, NULL),
};

#define define_hash_algorithm(hash_type, HASH_TYPE)                          \
	(t_hash_algorithm)                                                       \
	{                                                                        \
		.name = #hash_type,                                                  \
		.func = generic_digest_##hash_type,                                  \
		.block_byte_size = HASH_TYPE##_WORD_BLOCK_BIT_SIZE / OCTET_BIT_SIZE, \
		.hash_byte_size = HASH_TYPE##_DIGEST_BIT_SIZE / OCTET_BIT_SIZE,      \
	}

const static t_hash_algorithm	g_hash_md5 = define_hash_algorithm(md5, MD5);
const static t_hash_algorithm	g_hash_sha_224 = define_hash_algorithm(sha_224, SHA_224);
const static t_hash_algorithm	g_hash_sha_256 = define_hash_algorithm(sha_256, SHA_256);
const static t_hash_algorithm	g_hash_sha_384 = define_hash_algorithm(sha_384, SHA_384);
const static t_hash_algorithm	g_hash_sha_512 = define_hash_algorithm(sha_512, SHA_512);
const static t_hash_algorithm	g_hash_sha_512_224 = define_hash_algorithm(sha_512_224, SHA_512_224);
const static t_hash_algorithm	g_hash_sha_512_256 = define_hash_algorithm(sha_512_256, SHA_512_256);

#endif
