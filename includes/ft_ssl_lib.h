#ifndef FT_SSL_LIB_H
#define FT_SSL_LIB_H

#include "common.h"
#include "libft.h"
#include "elastic_buffer.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>

// subbyte_manipulation.c
void	set_bit_at(uint8_t* mem, uint64_t bit_pos, uint8_t bit);
void	subbyte_memcpy(uint8_t* dst, const uint8_t* src, uint8_t bit_from, uint8_t bit_to);
void	subbyte_memset(uint8_t* mem, const uint8_t bit, uint8_t bit_from, uint8_t bit_to);

#endif