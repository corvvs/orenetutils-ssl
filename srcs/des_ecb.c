#include "ft_ssl.h"
#include "ft_ssl_des_internal.h"

// 16進数字 1 文字を 0..15 に変換する. 変換できなければ -1.
static int	des_hex_value(char c) {
	c = ft_tolower(c);
	if ('0' <= c && c <= '9') {
		return c - '0';
	}
	if ('a' <= c && c <= 'f') {
		return c - 'a' + 10;
	}
	return -1;
}

// -k で与えられた 16 進鍵を 64bit 鍵オクテット列へ変換する.
// 短ければ右側をゼロ埋め, 長ければ切り詰める (OpenSSL の挙動に合わせる).
// 奇数桁の末尾は上位ニブルとして扱う (例: "FF1" -> FF 10 00 ..).
static void	des_hex_to_key(const char* hex, uint8_t key[DES_KEY_BYTE_SIZE]) {
	ft_bzero(key, DES_KEY_BYTE_SIZE);
	size_t	bi = 0;
	size_t	i = 0;
	while (hex[i] && bi < DES_KEY_BYTE_SIZE) {
		const int	hi = des_hex_value(hex[i]);
		if (hi < 0) {
			break;
		}
		++i;
		int	lo = 0;
		if (hex[i]) {
			const int	v = des_hex_value(hex[i]);
			if (v >= 0) {
				lo = v;
				++i;
			}
		}
		key[bi++] = (hi << 4) | lo;
	}
}

// ECB モードでの暗号化: PKCS#5/#7 パディングを付与し, ブロックごとに暗号化する.
static int	des_ecb_encrypt(t_master_des* m, const t_elastic_buffer* input, const t_des_subkeys* subkeys, int out_fd) {
	const size_t	len = input->used;
	const uint8_t	pad = DES_BLOCK_BYTE_SIZE - (len % DES_BLOCK_BYTE_SIZE);
	const size_t	out_len = len + pad;

	uint8_t*	buf = malloc(out_len);
	if (buf == NULL) {
		PRINT_ERROR(&m->master, "%s\n", strerror(errno));
		return 1;
	}
	ft_memcpy(buf, input->buffer, len);
	ft_memset(buf + len, pad, pad);

	for (size_t i = 0; i < out_len; i += DES_BLOCK_BYTE_SIZE) {
		const uint64_t	block = des_load_block(buf + i);
		des_store_block(des_crypt_block(block, subkeys, false), buf + i);
	}
	write(out_fd, buf, out_len);
	free(buf);
	return 0;
}

int	run_des_ecb(t_master* master, char** argv) {
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

	// 段階1: 鍵は -k による直接指定のみ (パスワード鍵導出は後続段階)
	if (pref->hex_key == NULL) {
		PRINT_ERROR(master, "%s\n", "key is required (-k)");
		return 1;
	}
	uint8_t	key[DES_KEY_BYTE_SIZE];
	des_hex_to_key(pref->hex_key, key);
	const t_des_subkeys	subkeys = des_key_schedule(des_load_block(key));

	// 段階1: 入力は標準入力, 出力は標準出力 (バイナリ)
	t_elastic_buffer	input = {};
	if (!create_buffer_stdin(master, &input)) {
		return 1;
	}
	const int	result = des_ecb_encrypt(&m, &input, &subkeys, STDOUT_FILENO);
	destroy_buffer(&input);
	return result;
}
