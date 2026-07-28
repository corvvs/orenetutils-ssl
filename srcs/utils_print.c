#include "ft_ssl.h"

// fd に len オクテットを書き切る.
bool	write_all(int fd, const void* data, size_t len) {
	const uint8_t*	head = data;
	while (len > 0) {
		const ssize_t	written = write(fd, head, len);
		// 0 が返ることは通常ないが, 進まないまま回り続けないよう失敗として扱う
		if (written <= 0) {
			return false;
		}
		head += written;
		len -= (size_t)written;
	}
	return true;
}

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

	// 書けなくなったら諦める.
	// 呼び出し側は表示用のマクロで, 失敗を伝える経路が無い.
	const size_t	batch_size = 1024;
	while (len >= batch_size + 1) {
		if (!write_all(fd, data, batch_size)) {
			return;
		}
		data += batch_size;
		len -= batch_size;
	}
	// len >= 1 のはず
	DEBUGOUT("data_is_test_like: %d", data_is_test_like);
	if (data_is_test_like && (char)data[len - 1] == '\n') {
		len -= 1;
	}
	write_all(fd, data, len);
}
