#include "ft_ssl.h"
#include "ft_ssl_des_internal.h"
#include "ft_ssl_base64_internal.h"

// [DES 共通フロントエンド]
// 入出力・base64(-a)・パディングの面倒を見て, ブロック処理だけを
// t_des_mode に委ねる. des-ecb / des-cbc / ... はモードを差し替えるだけ.

// ブロック列を先頭から順に処理する. 全モード共通のループ.
static void	des_crypt_blocks(
	uint8_t* buf,
	size_t len,
	const t_des_roundkeys* roundkeys,
	des_block_function* crypt, // crypt が何を行うかはモードおよび暗号化/復号化の指定に依存する
	uint64_t chain
) {
	for (size_t i = 0; i < len; i += DES_BLOCK_BYTE_SIZE) {
		const uint64_t	block = des_load_block(buf + i);
		des_store_block(crypt(block, roundkeys, &chain), buf + i);
	}
}

// PKCS#5/#7 パディングを検証して除去し, 平文長を *out_len に返す.
static bool	strip_padding(const uint8_t* buf, size_t len, size_t* out_len) {
	const uint8_t	pad = buf[len - 1];
	if (pad == 0 || pad > DES_BLOCK_BYTE_SIZE || pad > len) {
		return false;
	}
	for (size_t i = 0; i < pad; ++i) {
		if (buf[len - 1 - i] != pad) {
			return false;
		}
	}
	*out_len = len - pad;
	return true;
}

// 入力を読み込む (-i があればファイル, なければ標準入力)
static bool	read_des_input(t_master* master, const t_preference* pref, t_elastic_buffer* input) {
	if (pref->path_input != NULL) {
		return create_buffer_path(master, input, pref->path_input);
	}
	return create_buffer_stdin(master, input);
}

// 出力先を開く (-o があればファイル, なければ標準出力)
static int	open_des_output(t_master* master, const t_preference* pref) {
	if (pref->path_output == NULL) {
		return STDOUT_FILENO;
	}
	const int	fd = open(pref->path_output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		PRINT_ERROR(master, "%s: %s\n", pref->path_output, strerror(errno));
	}
	return fd;
}

// -a 指定の復号: 入力は base64 テキストなので, デコードして input を置き換える
static bool	decode_base64_input(t_master_des* m, t_elastic_buffer* input) {
	const t_master_base64	mb = { .master = m->master };
	t_base64_decode_state	state = { .input_buffer = input };

	chomp_buffer(input);
	if (!is_decodable_as_base64(&mb, &state)) {
		PRINT_ERROR(&m->master, "%s\n", "error reading input file");
		return false;
	}
	if (!run_decode(&mb, &state)) {
		PRINT_ERROR(&m->master, "%s\n", strerror(errno));
		destroy_buffer(&state.output_buffer);
		return false;
	}
	destroy_buffer(input);
	*input = state.output_buffer;
	return true;
}

// -a 指定の暗号化: 暗号文を base64 にして書き出す
static bool	write_base64_output(t_master_des* m, const uint8_t* data, size_t len, int out_fd) {
	t_elastic_buffer		source = { .buffer = (void*)data, .capacity = len, .used = len };
	t_base64_encode_state	state = { .input_buffer = &source, .out_fd = out_fd };

	run_encode(&state);
	const bool	result = base64_write_lines(out_fd, &state.output_buffer, DES_BASE64_LINE_LENGTH);
	if (!result) {
		PRINT_ERROR(&m->master, "%s\n", strerror(errno));
	}
	destroy_buffer(&state.output_buffer);
	return result;
}

static int	des_encrypt(
	t_master_des* m,
	const t_elastic_buffer* input,
	const t_des_roundkeys* roundkeys,
	const t_des_mode* mode,
	int out_fd
) {
	// パディングは常に 1 .. DES_BLOCK_BYTE_SIZE バイト付く
	const size_t	len = input->used;
	const uint8_t	pad = DES_BLOCK_BYTE_SIZE - (len % DES_BLOCK_BYTE_SIZE);
	const size_t	out_len = len + pad;

	uint8_t*	buf = malloc(out_len);
	if (buf == NULL) {
		PRINT_ERROR(&m->master, "%s\n", strerror(errno));
		return 1;
	}
	if (len > 0) {
		ft_memcpy(buf, input->buffer, len);
	}
	ft_memset(buf + len, pad, pad);

	des_crypt_blocks(buf, out_len, roundkeys, mode->encrypt, m->iv);

	int	result = 0;
	if (m->pref.is_base64) {
		result = write_base64_output(m, buf, out_len, out_fd) ? 0 : 1;
	} else {
		write(out_fd, buf, out_len);
	}
	free(buf);
	return result;
}

static int	des_decrypt(
	t_master_des* m,
	const t_elastic_buffer* input,
	const t_des_roundkeys* roundkeys,
	const t_des_mode* mode,
	int out_fd
) {
	const size_t	len = input->used;
	if (len == 0 || len % DES_BLOCK_BYTE_SIZE != 0) {
		PRINT_ERROR(&m->master, "%s\n", "bad decrypt: wrong final block length");
		return 1;
	}

	uint8_t*	buf = malloc(len);
	if (buf == NULL) {
		PRINT_ERROR(&m->master, "%s\n", strerror(errno));
		return 1;
	}
	ft_memcpy(buf, input->buffer, len);

	des_crypt_blocks(buf, len, roundkeys, mode->decrypt, m->iv);

	size_t	out_len;
	if (!strip_padding(buf, len, &out_len)) {
		PRINT_ERROR(&m->master, "%s\n", "bad decrypt");
		free(buf);
		return 1;
	}
	write(out_fd, buf, out_len);
	free(buf);
	return 0;
}

// DES 全モード共通のフロントエンド関数
int	run_des_generic(t_master* master, char** argv, const t_des_mode* mode) {
	t_master_des	m = {
		.master = *master,
	};
	t_preference*	pref = &m.pref;
	int parsed_count = parse_options_des(master, argv, pref);
	if (parsed_count < 0) {
		return 1;
	}
	argv += parsed_count;
	if (*argv != NULL) {
		PRINT_ERROR(master, "unexpected argument: %s\n", *argv);
		return 1;
	}

	// とりあえず -k (hex-string表現の鍵)がないとダメということにしておく
	if (pref->hex_key == NULL) {
		PRINT_ERROR(master, "%s\n", "key is required (-k)");
		return 1;
	}
	// TODO: -k 不要化
	// - stdin から鍵データを取得
	// - パスフレーズ から鍵を導出 (pbkdf2)
	// など
	const t_des_roundkeys	roundkeys = des_roundkeys_from_hex(pref->hex_key);

	t_elastic_buffer	input = {};
	if (!read_des_input(master, pref, &input)) {
		return 1;
	}

	// -a 指定の復号では, 先に入力の base64 をデコードしておく
	bool	ready = true;
	if (pref->is_decode && pref->is_base64) {
		ready = decode_base64_input(&m, &input);
	}

	int	result = 1;
	if (ready) {
		const int	out_fd = open_des_output(master, pref);
		if (out_fd >= 0) {
			result = pref->is_decode
				? des_decrypt(&m, &input, &roundkeys, mode, out_fd)
				: des_encrypt(&m, &input, &roundkeys, mode, out_fd);
			if (pref->path_output != NULL) {
				close(out_fd);
			}
		}
	}
	destroy_buffer(&input);
	return result;
}
