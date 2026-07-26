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

	base64_chomp_newline(input);
	if (!is_decodable_as_base64(&mb, &state)) {
		PRINT_ERROR(&m->master, "%s\n", "error reading input file");
		return false;
	}
	if (!base64_decode_buffer(&mb, &state)) {
		PRINT_ERROR(&m->master, "%s\n", strerror(errno));
		destroy_buffer(&state.output_buffer);
		return false;
	}
	destroy_buffer(input);
	*input = state.output_buffer;
	return true;
}

// 復号時: 入力の先頭にある "Salted__" + salt を取り出し, 入力から取り除く.
// ヘッダがなければ何もせず false を返す.
static bool	take_salt_header(t_elastic_buffer* input, uint8_t salt[DES_SALT_BYTE_SIZE]) {
	if (input->used < DES_SALT_HEADER_BYTE_SIZE) {
		return false;
	}
	if (ft_memcmp(input->buffer, DES_SALT_MAGIC, DES_SALT_MAGIC_BYTE_SIZE) != 0) {
		return false;
	}
	ft_memcpy(salt, (const uint8_t*)input->buffer + DES_SALT_MAGIC_BYTE_SIZE, DES_SALT_BYTE_SIZE);
	eb_truncate_front(input, DES_SALT_HEADER_BYTE_SIZE);
	return true;
}

// パスワードから鍵を導出するのに使う salt を決める.
//   復号: 入力にヘッダがあればそこから読む. なければ -s を使う.
//   暗号化: -s があればそれを使い, ヘッダは付けない (OpenSSL 3.x に合わせる).
//          -s がなければ乱数で作り, ヘッダを前置する.
static bool	resolve_salt(t_master_des* m, t_elastic_buffer* input, t_des_secret* secret) {
	const t_preference*	pref = &m->pref;

	if (pref->is_decode) {
		// OpenSSL 1.1.1 が作った暗号文は -S 指定時でもヘッダを持つので,
		// -s の有無に関わらずまずヘッダを見る.
		if (take_salt_header(input, secret->salt)) {
			return true;
		}
		if (pref->hex_salt != NULL) {
			des_bytes_from_hex(pref->hex_salt, secret->salt);
			return true;
		}
		PRINT_ERROR(&m->master, "%s\n", "bad magic number");
		return false;
	}

	if (pref->hex_salt != NULL) {
		des_bytes_from_hex(pref->hex_salt, secret->salt);
		return true;
	}
	// ユーザー入力から salt を得られなかったので, 乱数から生成
	if (!des_random_salt(secret->salt)) {
		PRINT_ERROR(&m->master, "%s\n", "unable to generate salt");
		return false;
	}
	secret->emit_salt_header = true;
	return true;
}

// 鍵と IV を決める.
// -k / -v による直接指定を優先し, 足りない分をパスワードから導出する.
static bool	setup_secret(t_master_des* m, const t_des_mode* mode, t_elastic_buffer* input, t_des_secret* secret) {
	const t_preference*	pref = &m->pref;
	const bool			needs_iv = mode->uses_iv;

	ft_bzero(secret, sizeof(*secret));

	// -k がなければ鍵をパスワードから作るしかない.
	// -p が明示されている場合も (鍵が -k で与えられていても) 導出する.
	const bool	use_password = (pref->password != NULL) || (pref->hex_key == NULL);
	if (!use_password && needs_iv && pref->hex_iv == NULL) {
		// 鍵を直接もらっているのに IV だけ足りない場合は OpenSSL 同様エラー
		PRINT_ERROR(&m->master, "%s\n", "iv undefined");
		return false;
	}

	uint64_t	derived_key = 0;
	uint64_t	derived_iv = 0;
	if (use_password) {
		if (!resolve_salt(m, input, secret)) {
			return false;
		}
		// パスワードは静的領域に残さないよう, この呼び出しの間だけ持つ
		char		password_buffer[DES_PASSWORD_MAX_LEN + 1];
		const char*	password = des_acquire_password(m, password_buffer, sizeof(password_buffer));
		if (password == NULL) {
			return false;
		}
		if (!des_derive_key_iv(password, secret->salt, needs_iv, &derived_key, &derived_iv)) {
			PRINT_ERROR(&m->master, "%s\n", "unable to derive key from password");
			return false;
		}
	}

	secret->roundkeys = (pref->hex_key != NULL)
		? des_roundkeys_from_hex(pref->hex_key)
		: des_key_schedule(derived_key);
	if (needs_iv) {
		secret->iv = (pref->hex_iv != NULL)
			? des_block_from_hex(pref->hex_iv)
			: derived_iv;
	}
	return true;
}

// -a 指定の暗号化: 暗号文を base64 にして書き出す
static bool	write_base64_output(t_master_des* m, const uint8_t* data, size_t len, int out_fd) {
	t_elastic_buffer		source = { .buffer = (void*)data, .capacity = len, .used = len };
	t_base64_encode_state	state = { .input_buffer = &source, .out_fd = out_fd };

	base64_encode_buffer(&state);
	const bool	result = base64_write_lines(out_fd, &state.output_buffer, BASE64_LINE_LENGTH);
	if (!result) {
		PRINT_ERROR(&m->master, "%s\n", strerror(errno));
	}
	destroy_buffer(&state.output_buffer);
	return result;
}

static int	des_encrypt(
	t_master_des* m,
	const t_elastic_buffer* input,
	const t_des_secret* secret,
	const t_des_mode* mode,
	int out_fd
) {
	// パディングは常に 1 .. DES_BLOCK_BYTE_SIZE バイト付く
	const size_t	len = input->used;
	const uint8_t	pad = DES_BLOCK_BYTE_SIZE - (len % DES_BLOCK_BYTE_SIZE);
	const size_t	body_len = len + pad;
	// salt をランダム生成した場合は "Salted__" + salt を暗号文の前に置く.
	// (-a 指定時はこれも含めて base64 にする)
	const size_t	header_len = secret->emit_salt_header ? DES_SALT_HEADER_BYTE_SIZE : 0;

	uint8_t*	buf = malloc(header_len + body_len);
	if (buf == NULL) {
		PRINT_ERROR(&m->master, "%s\n", strerror(errno));
		return 1;
	}
	if (header_len > 0) {
		ft_memcpy(buf, DES_SALT_MAGIC, DES_SALT_MAGIC_BYTE_SIZE);
		ft_memcpy(buf + DES_SALT_MAGIC_BYTE_SIZE, secret->salt, DES_SALT_BYTE_SIZE);
	}
	uint8_t*	body = buf + header_len;
	if (len > 0) {
		ft_memcpy(body, input->buffer, len);
	}
	ft_memset(body + len, pad, pad);

	des_crypt_blocks(body, body_len, &secret->roundkeys, mode->encrypt, secret->iv);

	int	result = 0;
	if (m->pref.is_base64) {
		result = write_base64_output(m, buf, header_len + body_len, out_fd) ? 0 : 1;
	} else {
		write(out_fd, buf, header_len + body_len);
	}
	free(buf);
	return result;
}

static int	des_decrypt(
	t_master_des* m,
	const t_elastic_buffer* input,
	const t_des_secret* secret,
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

	des_crypt_blocks(buf, len, &secret->roundkeys, mode->decrypt, secret->iv);

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

	// 鍵の準備より先に入力を読む.
	// 復号では salt が暗号文先頭の "Salted__" ヘッダに入っていることがあり,
	// 入力を得るまで鍵を決められないため.
	t_elastic_buffer	input = {};
	if (!read_des_input(master, pref, &input)) {
		return 1;
	}

	// -a 指定の復号では, 先に入力の base64 をデコードしておく
	// (でないと salt ヘッダが見えないことがある)
	bool	ready = true;
	if (pref->is_decode && pref->is_base64) {
		ready = decode_base64_input(&m, &input);
	}

	t_des_secret	secret;
	if (ready) {
		ready = setup_secret(&m, mode, &input, &secret);
	}

	int	result = 1;
	if (ready) {
		const int	out_fd = open_des_output(master, pref);
		if (out_fd >= 0) {
			result = pref->is_decode
				? des_decrypt(&m, &input, &secret, mode, out_fd)
				: des_encrypt(&m, &input, &secret, mode, out_fd);
			if (pref->path_output != NULL) {
				close(out_fd);
			}
		}
	}
	destroy_buffer(&input);
	return result;
}
