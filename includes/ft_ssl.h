#ifndef FT_SSL_H
#define FT_SSL_H

#include "ft_ssl_md5.h"
#include "utils_endian.h"
#include "ft_ssl_structure.h"
#include "ft_ssl_lib.h"

// md5.c
void digest_md5(const t_preference_digest* pref, const t_message* message);

// sha_***.c
void digest_sha_224(const t_preference_digest* pref, const t_message* message);
void digest_sha_256(const t_preference_digest* pref, const t_message* message);
void digest_sha_384(const t_preference_digest* pref, const t_message* message);
void digest_sha_512(const t_preference_digest* pref, const t_message* message);
void digest_sha_512_224(const t_preference_digest* pref, const t_message* message);
void digest_sha_512_256(const t_preference_digest* pref, const t_message* message);

// preference.c
int	parse_options_digest(const t_master* master, char** argv, t_preference_digest* pref_ptr);

// read_file.c
bool	read_file(const t_master* master, int ifd, t_elastic_buffer* buffer_ptr);

// run_command.c
int	run_command(const t_master* master, char **argv);

// utils_endian.c
bool is_little_endian(void);

// utils_error.c
void print_error_by_message(const t_master* master, const char* message);

// utils_print.c
void put_bitstream(int fd, const uint8_t* data, size_t bit_len);

#define PRINT_ERROR(master, format, ...) yoyo_dprintf(STDERR_FILENO, "%s: %s: " format, master->program_name, master->command_name, __VA_ARGS__)

#endif
