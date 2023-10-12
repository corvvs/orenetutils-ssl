#include "ft_ssl.h"
#include "ft_ssl_base64_internal.h"

const char *base64_encode_table =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789"
	"+/";

static void	run_encode(t_base64_encode_state* state) {

	uint8_t	sextet = 0;
	const unsigned char*	buffer = state->input_buffer->buffer;
	const size_t			input_used = state->input_buffer->used;
	for (size_t i = 0; i < input_used; ++i) {
		unsigned char encoding_byte = buffer[i];
		switch (i % 3) {
			case 0:
				// msb6, lsb2
				sextet |= (encoding_byte & 0b11111100) >> 2;
				eb_push(&state->output_buffer, &base64_encode_table[sextet], 1, 1);
				sextet = 0;
				sextet |= (encoding_byte & 0b00000011) << 4;
				break;
			case 1:
				// msb4, lsb4
				sextet |= (encoding_byte & 0b11110000) >> 4;
				eb_push(&state->output_buffer, &base64_encode_table[sextet], 1, 1);
				sextet = 0;
				sextet |= (encoding_byte & 0b00001111) << 2;
				break;
			case 2:
				// msb2, lsb6
				sextet |= (encoding_byte & 0b11000000) >> 6;
				eb_push(&state->output_buffer, &base64_encode_table[sextet], 1, 1);
				sextet = 0;
				sextet |= (encoding_byte & 0b00111111);
				eb_push(&state->output_buffer, &base64_encode_table[sextet], 1, 1);
				sextet = 0;
				break;
		}
	}
	if (input_used % 3 > 0) {
		eb_push(&state->output_buffer, &base64_encode_table[sextet], 1, 1);
	}
	while (state->output_buffer.used % 4 > 0) {
		eb_push(&state->output_buffer, "=", 1, 1);
	}
}

#define LINE_LENGTH 76
static void	write_out_buffer(const t_master_base64* m, t_base64_encode_state* state) {
	size_t	n = 0;
	while (n + LINE_LENGTH < state->output_buffer.used) {
		ssize_t size = write(state->out_fd, state->output_buffer.buffer + n, LINE_LENGTH);
		if (size < 0) {
			PRINT_ERROR(&(m->master), "%s\n", strerror(errno));
			return;
		}
		write(state->out_fd, "\n", 1);
		n += size;
	}
	if (state->output_buffer.used > n) {
		ssize_t size = write(state->out_fd, state->output_buffer.buffer + n, state->output_buffer.used - n);
		if (size < 0) {
			PRINT_ERROR(&(m->master), "%s\n", strerror(errno));
			return;
		}
		write(state->out_fd, "\n", 1);
	}
}

// **オンラインで** base64エンコードを行う
int	base64_encode(t_master_base64* m, t_elastic_buffer* input, int out_fd) {
	t_base64_encode_state	state = {
		.input_buffer = input,
		.out_fd = out_fd,
	};
	run_encode(&state);
	write_out_buffer(m, &state);
	destroy_buffer(&state.output_buffer);
	return 0;
}
