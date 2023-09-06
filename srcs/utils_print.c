#include "ft_ssl.h"

void put_bytestream(int fd, const uint8_t* data, size_t len) {
	const size_t	batch_size = 1024;
	while (len >= batch_size) {
		write(fd, data, batch_size);
		data += batch_size;
		len -= batch_size;
	}
	write(fd, data, len);
}

