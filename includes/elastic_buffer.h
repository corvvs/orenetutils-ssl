/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elastic_buffer.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: corvvs <corvvs@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/09 21:16:22 by corvvs            #+#    #+#             */
/*   Updated: 2023/09/06 14:55:19 by corvvs           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

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
}				t_elastic_buffer;

// elastic_buffer.c
bool	push_to_elastic_buffer(t_elastic_buffer* elastic_buffer, const void *data, size_t data_size, size_t minimum_cap);

#endif
