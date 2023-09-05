#ifndef FT_SSL_H
#define FT_SSL_H

#include "ft_ssl_md5.h"
#include "utils_endian.h"

// md5.c
void	digest_md5(const uint8_t* message, size_t bit_len);

// sha_2.c
void	digest_sha_2(const uint8_t* message, size_t bit_len);

// utils_endian.h
bool	is_little_endian(void);

#endif