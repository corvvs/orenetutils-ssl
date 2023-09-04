#ifndef FT_SSL_H
#define FT_SSL_H

#include "ft_ssl_md5.h"

// md5.c
t_md5_digest md5_hash(const uint8_t *message, uint64_t message_len);

#endif