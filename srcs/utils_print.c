#include "ft_ssl.h"

void put_bitstream(int fd, const uint8_t* data, size_t bit_len) {
	// ビット列 data を fd に出力する
	// ただし, data の末尾バイトが '\n' なら, 末尾だけ出力しない
	size_t len = bit_len > 0                                                                 \
		? (bit_len - 1) / OCTET_BIT_SIZE + 1
		: 0;

	if (len == 0) { return; }

	const size_t	batch_size = 1024;
	while (len >= batch_size + 1) {
		write(fd, data, batch_size);
		data += batch_size;
		len -= batch_size;
	}
	// len >= 1 のはず
	if ((char)data[len - 1] == '\n') {
		len -= 1;
	}
	write(fd, data, len);
}
