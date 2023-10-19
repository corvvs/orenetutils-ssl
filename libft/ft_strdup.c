/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: corvvs <corvvs@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/02/16 19:27:36 by corvvs            #+#    #+#             */
/*   Updated: 2023/10/18 11:17:44 by corvvs           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	*ft_strdup(const char *s1)
{
	return (ft_strndup(s1, -1));
}

char	*ft_strndup(const char *s1, size_t n)
{
	const size_t	len = ft_strnlen(s1, n);
	char			*dup;

	dup = malloc(sizeof(char) * (len + 1));
	if (dup != NULL)
	{
		ft_memcpy(dup, s1, len);
		dup[len] = '\0';
	}
	return (dup);
}

void*	ft_memdup(const void* mem, size_t len) {
	void*	dup = malloc(len);
	if (dup != NULL) {
		ft_memcpy(dup, mem, len);
	}
	return dup;
}
