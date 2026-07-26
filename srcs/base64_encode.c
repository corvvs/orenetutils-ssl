#include "ft_ssl.h"
#include "ft_ssl_base64_internal.h"

const char *base64_encode_table =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789"
	"+/";

void	base64_encode_buffer(const void* src, size_t len, t_elastic_buffer* out) {

	uint8_t	sextet = 0;
	const unsigned char*	buffer = src;
	for (size_t i = 0; i < len; ++i) {
		unsigned char encoding_byte = buffer[i];
		switch (i % 3) {
			case 0:
				// msb6, lsb2
				sextet |= (encoding_byte & 0b11111100) >> 2;
				eb_push(out, &base64_encode_table[sextet], 1, 1);
				sextet = 0;
				sextet |= (encoding_byte & 0b00000011) << 4;
				break;
			case 1:
				// msb4, lsb4
				sextet |= (encoding_byte & 0b11110000) >> 4;
				eb_push(out, &base64_encode_table[sextet], 1, 1);
				sextet = 0;
				sextet |= (encoding_byte & 0b00001111) << 2;
				break;
			case 2:
				// msb2, lsb6
				sextet |= (encoding_byte & 0b11000000) >> 6;
				eb_push(out, &base64_encode_table[sextet], 1, 1);
				sextet = 0;
				sextet |= (encoding_byte & 0b00111111);
				eb_push(out, &base64_encode_table[sextet], 1, 1);
				sextet = 0;
				break;
		}
	}
	if (len % 3 > 0) {
		eb_push(out, &base64_encode_table[sextet], 1, 1);
	}
	while (out->used % 4 > 0) {
		eb_push(out, "=", 1, 1);
	}
}

// エンコード結果を line_length 文字ごとに改行しつつ書き出す.
bool	base64_write_lines(int out_fd, const t_elastic_buffer* buffer, size_t line_length) {
	size_t	n = 0;
	while (n + line_length < buffer->used) {
		ssize_t size = write(out_fd, buffer->buffer + n, line_length);
		if (size < 0) {
			return false;
		}
		write(out_fd, "\n", 1);
		n += size;
	}
	if (buffer->used > n) {
		ssize_t size = write(out_fd, buffer->buffer + n, buffer->used - n);
		if (size < 0) {
			return false;
		}
		write(out_fd, "\n", 1);
	}
	return true;
}

// **オンラインで** base64エンコードを行う
int	base64_encode(t_master_base64* m, t_elastic_buffer* input, int out_fd) {
	t_elastic_buffer	encoded = {};

	base64_encode_buffer(input->buffer, input->used, &encoded);
	if (!base64_write_lines(out_fd, &encoded, BASE64_LINE_LENGTH)) {
		PRINT_ERROR(&(m->master), "%s\n", strerror(errno));
	}
	destroy_buffer(&encoded);
	return 0;
}
