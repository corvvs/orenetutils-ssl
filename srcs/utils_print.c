#include "ft_ssl.h"

static bool	is_binary_char(int ch) {
	return !(ft_isprint(ch) || ch == '\n' || ch == '\t');
}

static bool	is_text_like(const uint8_t* data, size_t bit_len) {
	for (size_t i = 0; i < bit_len; ++i) {
		if (is_binary_char((char)data[i])) {
			return false;
		}
	}
	return true;
}

void put_bitstream(int fd, const uint8_t* data, size_t bit_len) {
	// ビット列 data を fd に出力する
	// ただし, data が text-like かつ data の末尾バイトが '\n' なら, 末尾だけ出力しない
	size_t len = bit_len > 0                                                                 \
		? (bit_len - 1) / OCTET_BIT_SIZE + 1
		: 0;
	const bool	data_is_test_like = is_text_like(data, len);

	if (len == 0) { return; }

	const size_t	batch_size = 1024;
	while (len >= batch_size + 1) {
		write(fd, data, batch_size);
		data += batch_size;
		len -= batch_size;
	}
	// len >= 1 のはず
	DEBUGOUT("data_is_test_like: %d", data_is_test_like);
	if (data_is_test_like && (char)data[len - 1] == '\n') {
		len -= 1;
	}
	write(fd, data, len);
}
