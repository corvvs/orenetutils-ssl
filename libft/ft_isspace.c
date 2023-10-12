#include "libft.h"

int	ft_isspace(int ch)
{
	unsigned int	c = ch;
	return (c < 64 && !(c & ~63u) && (0x100003e00ull & (1ull << c)));
}
