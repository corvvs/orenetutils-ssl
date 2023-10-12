#include "ft_ssl.h"
#include "ft_ssl_base64_internal.h"

const char *base64_encode_table =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789"
	"+/";

static ssize_t	read_to_buffer(const t_master_base64* m, t_base64_encode_state* state) {
	// EOFかエラーが来ない場合, かならず目一杯読むこと
	state->input_used = 0;
	while (state->input_used < sizeof(state->input_buffer)) {
		ssize_t size = read(state->in_fd, state->input_buffer + state->input_used, sizeof(state->input_buffer) - state->input_used);
		if (size < 0) {
			PRINT_ERROR(&(m->master), "%s\n", strerror(errno));
			state->input_used = 0;
			return size;
		}
		if (size == 0) {
			state->input_exhausted = true;
			break;
		}
		state->input_used += size;
	}
	return state->input_used;
}

static void	run_encode(t_base64_encode_state* state) {
	// input_buffer が目一杯でない時は, 必ず入力が終わっていると考えてよい.
	// ただし input_buffer が目一杯であっても入力が続く可能性がある.
	// (この性質により, state が持つべきパラメータが減る)

	state->output_used = 0;
	uint8_t	sextet = 0;
	for (size_t i = 0; i < state->input_used; ++i) {
		unsigned char encoding_byte = state->input_buffer[i];
		switch (i % 3) {
			case 0:
				// msb6, lsb2
				sextet |= (encoding_byte & 0b11111100) >> 2;
				state->output_buffer[state->output_used++] = base64_encode_table[sextet];
				sextet = 0;
				sextet |= (encoding_byte & 0b00000011) << 4;
				break;
			case 1:
				// msb4, lsb4
				sextet |= (encoding_byte & 0b11110000) >> 4;
				state->output_buffer[state->output_used++] = base64_encode_table[sextet];
				sextet = 0;
				sextet |= (encoding_byte & 0b00001111) << 2;
				break;
			case 2:
				// msb2, lsb6
				sextet |= (encoding_byte & 0b11000000) >> 6;
				state->output_buffer[state->output_used++] = base64_encode_table[sextet];
				sextet = 0;
				sextet |= (encoding_byte & 0b00111111);
				state->output_buffer[state->output_used++] = base64_encode_table[sextet];
				sextet = 0;
				break;
		}
	}
	if (state->input_exhausted) {
		if (state->input_used % 3 > 0) {
			state->output_buffer[state->output_used++] = base64_encode_table[sextet];
		}
		while (state->output_used % 4 > 0) {
			state->output_buffer[state->output_used] = '=';
			state->output_used += 1;
		}
	}
}

static void	write_out_buffer(const t_master_base64* m, t_base64_encode_state* state) {
	ssize_t size = write(state->out_fd, state->output_buffer, state->output_used);
	if (size < 0) {
		PRINT_ERROR(&(m->master), "%s\n", strerror(errno));
	}
	state->output_used = 0;
}

// **オンラインで** base64エンコードを行う
int	base64_encode(t_master_base64* m) {
	t_base64_encode_state	state = {
		.in_fd = STDIN_FILENO,
		.out_fd = STDOUT_FILENO,
	};
	while (!state.input_exhausted) {
		if (read_to_buffer(m, &state) < 0) {
			break;
		}
		run_encode(&state);
		write_out_buffer(m, &state);
	}
	yoyo_dprintf(STDOUT_FILENO, "\n");
	return 0;
}
