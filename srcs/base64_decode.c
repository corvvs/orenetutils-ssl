#include "ft_ssl.h"
#include "ft_ssl_base64_internal.h"

static const int8_t base64_decode_table[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59,
	60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6, 
	 7,  8,  9, 10, 11, 12, 13, 14, 
	15, 16, 17, 18, 19, 20, 21, 22, 
	23, 24, 25, -1, -1, -1, -1, -1, 
	-1, 26, 27, 28, 29, 30, 31, 32, 
	33, 34, 35, 36, 37, 38, 39, 40, 
	41, 42, 43, 44, 45, 46, 47, 48, 
	49, 50, 51, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1
};

static bool	is_base64_char(unsigned char c) {
	return (c < 128 && base64_decode_table[(int)c] >= 0);
}

void	base64_chomp_newline(t_elastic_buffer* buffer) {
	if (buffer->used == 0) {
		return;
	}
	char c = ((char*)buffer->buffer)[buffer->used - 1];
	if (c != '\n') {
		return;
	}
	buffer->used -= 1;
}

static void	write_decoded(int out_fd, const t_elastic_buffer* decoded) {
	size_t	n = 0;
	while (n + 1024 < decoded->used) {
		ssize_t size = write(out_fd, decoded->buffer + n, 1024);
		if (size < 0) {
			return;
		}
		n += size;
	}
	write(out_fd, decoded->buffer + n, decoded->used - n);
}

// 与えられたデータがbase64デコード可能な文字列かどうかを判定する
bool	is_decodable_as_base64(const void* src, size_t len) {
	// [判定処理]
	// - (空白文字は無視して判定する)
	// - 末尾に2個以下の`=`があること
	//   - 文字数が4の倍数になるまで`=`でパディングするため一見3個もありえそうだが, 実はそうはならない
	//   - パディング個数としてあり得るのは 0, 2, 1 のみ (それぞれデータサイズを3で割ったあまりが 0, 1, 2 の場合に対応する)
	// - 末尾までの文字がすべて使用可能文字であること
	// - 全体の長さが4の倍数であること

	const char* 	buffer = src;
	const size_t	buffer_len = len;
	size_t			data_len = 0;
	size_t			equals = 0;
	bool			has_encountered_equal = false;
	for (size_t i = 0; i < buffer_len; ++i) {
		char	c = buffer[i];
		if (ft_isspace(c)) {
			continue;
		}
		if (c == '=') {
			has_encountered_equal = true;
			equals += 1;
			if (equals > 2) {
				return false;
			}
		} else if (is_base64_char(c)) {
			if (has_encountered_equal) {
				return false;
			}
			data_len += 1;
		} else {
			return false;
		}
	}
	if ((data_len + equals) % 4 != 0) {
		return false;
	}
	return true;
}

// [各種データサイズの関係]
// - ソース文字列の長さ(=抜き)      S
// - ソース文字列から得られるビット数 B = 6S
// - ゼロパディング後ビット数        P = (B + 7) / 8 * 8
// - デコード後のバイト数           D = P / 8 = (B + 7) / 8 = (6S + 7) / 8

// base64エンコードされたデータをデコードする
bool	base64_decode_buffer(const void* src, size_t len, t_elastic_buffer* out) {
	// 2-pass で実装する.
	// 1-pass でもいけるが extend 回数が増える.
	// メモリアロケーションの方がコストが重そう, という判断.
	// (測れや...)

	const char* 	source = src;
	const size_t	source_len = len;

	// もう1度長さを測る
	size_t		data_len = 0;
	for (size_t i = 0; i < source_len; ++i) {
		char	c = source[i];
		if (ft_isspace(c)) {
			continue;
		}
		if (c == '=') {
			break;
		}
		data_len += 1;
	}
	// デコード後バイト数
	const size_t	decoded_len = (data_len * 6 + 7) / 8;
	// デコードバッファを必要分確保する
	if (!eb_reserve(out, decoded_len)) {
		return false;
	}
	// デコード実施
	unsigned char*	dest = out->buffer;
	unsigned char	decoded_bit = 0;
	size_t	di = 0;
	for (size_t i = 0; i < source_len; ++i) {
		char	c = source[i];
		if (ft_isspace(c)) {
			continue;
		}
		if (c == '=') {
			break;
		}
		const uint8_t	sextet = base64_decode_table[(uint8_t)c];
		switch (di % 4) {
			case 0:
				decoded_bit |= (sextet << 2);
				break;
			case 1:
				decoded_bit |= sextet >> 4;
				dest[out->used++] = decoded_bit;
				decoded_bit = sextet << 4;
				break;
			case 2:
				decoded_bit |= sextet >> 2;
				dest[out->used++] = decoded_bit;
				decoded_bit = sextet << 6;
				break;
			case 3:
				decoded_bit |= sextet;
				dest[out->used++] = decoded_bit;
				decoded_bit = 0;
				break;
		}
		di += 1;
	}

	return true;
}

int	base64_decode(t_master_base64* m, t_elastic_buffer* input, int out_fd) {
	base64_chomp_newline(input);

	if (!is_decodable_as_base64(input->buffer, input->used)) {
		PRINT_ERROR(&(m->master), "%s\n", "invalid base64 input");
		return 1;
	}
	t_elastic_buffer	decoded = {};
	if (!base64_decode_buffer(input->buffer, input->used, &decoded)) {
		PRINT_ERROR(&(m->master), "%s\n", strerror(errno));
		return 1;
	}

	write_decoded(out_fd, &decoded);
	destroy_buffer(&decoded);
	return 0;
}
