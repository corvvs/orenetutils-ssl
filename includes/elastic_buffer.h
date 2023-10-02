#ifndef ELASTIC_BUFFER_H
#define ELASTIC_BUFFER_H

#include <stdlib.h>
#include <stdbool.h>
#include "ft_ssl_lib.h"

// [elastic_buffer]
// 必要に応じてサイズが伸長するバッファ
typedef struct	s_elastic_buffer {
	void*	buffer;
	size_t	capacity;
	size_t	used;
	bool	eof_reached;
}				t_elastic_buffer;

// elastic_buffer.c
bool	eb_push(t_elastic_buffer* elastic_buffer, const void *data, size_t data_size, size_t minimum_cap);
void	eb_truncate_front(t_elastic_buffer* elastic_buffer, size_t data_size);
t_elastic_buffer	eb_release(t_elastic_buffer* from);


#endif
