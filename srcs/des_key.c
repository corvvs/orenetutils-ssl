#include "ft_ssl.h"
#include "ft_ssl_des_internal.h"
#include <termios.h>

// [DES の鍵・初期化ベクトルの準備]

extern t_pbkdf2_prf	g_prf_hmac_sha_256;

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

// 16 進文字列を size オクテットへ変換する.
// 短ければ右側をゼロ埋め, 長ければ切り詰める (OpenSSL の挙動に合わせる).
// 奇数桁の末尾は上位ニブルとして扱う (例: "FF1" -> FF 10 00 ..).
static void	des_hex_to_bytes(const char* hex, uint8_t* block, size_t size) {
	ft_bzero(block, size);
	size_t	bi = 0;
	size_t	i = 0;
	while (hex[i] && bi < size) {
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
		block[bi++] = (hi << 4) | lo;
	}
}

void	des_bytes_from_hex(const char* hex, uint8_t* out, size_t size) {
	des_hex_to_bytes(hex, out, size);
}

uint64_t	des_block_from_hex(const char* hex) {
	uint8_t	block[DES_BLOCK_BYTE_SIZE];
	des_hex_to_bytes(hex, block, sizeof(block));
	return des_load_block(block);
}

t_des_keys	des_keys_from_bytes(const uint8_t* material, size_t count) {
	t_des_keys	keys = { .count = count };
	for (size_t i = 0; i < count; ++i) {
		keys.roundkeys[i] = des_key_schedule(des_load_block(material + i * DES_KEY_BYTE_SIZE));
	}
	return keys;
}

bool	des_derive_key_iv(
	const char* password,
	const uint8_t salt[DES_SALT_BYTE_SIZE],
	size_t key_byte_size,
	bool needs_iv,
	uint8_t* key_material,
	uint64_t* iv
) {
	// 導出結果は 鍵 || IV の順に並ぶ. IV を使わないモードでは鍵の分だけ導出する.
	const size_t	dklen = key_byte_size + (needs_iv ? DES_BLOCK_BYTE_SIZE : 0);
	const t_generic_message	pw = {
		.message = (void*)password,
		.byte_size = ft_strlen(password),
	};
	const t_generic_message	sl = {
		.message = (void*)salt,
		.byte_size = DES_SALT_BYTE_SIZE,
	};

	t_generic_message	dk = pbkdf2(&g_prf_hmac_sha_256, &pw, &sl, DES_PBKDF2_ITERATIONS, dklen);
	if (is_failed_generic_message(&dk)) {
		return false;
	}
	const uint8_t*	material = dk.message;
	ft_memcpy(key_material, material, key_byte_size);
	if (needs_iv) {
		*iv = des_load_block(material + key_byte_size);
	}
	destroy_generic_message(&dk);
	return true;
}

// OpenSSL に倣い "enter <コマンド名> encryption password:" の形にする.
// コマンド名はそのまま (小文字) 使う: 1.1.1 の表記に合わせている (3.x は大文字).
static void	build_password_prompt(const t_master_des* m, char* buffer, size_t size) {
	ft_strlcpy(buffer, "enter ", size);
	ft_strlcat(buffer, m->master.command_name, size);
	ft_strlcat(buffer, m->pref.is_decode ? " decryption password:" : " encryption password:", size);
}

typedef enum e_password_read
{
	PASSWORD_READ_OK,
	PASSWORD_READ_EOF,
	PASSWORD_READ_TOO_LONG,
	PASSWORD_READ_FAILED,
}	t_password_read;

// 端末ならエコーを止める.
static bool	mute_tty_echo(int fd, struct termios* saved) {
	if (tcgetattr(fd, saved) != 0) {
		return false;
	}
	struct termios	muted = *saved;
	muted.c_lflag &= ~(tcflag_t)ECHO;
	return tcsetattr(fd, TCSAFLUSH, &muted) == 0;
}

// 改行までを buffer に読む (改行自体は含めない).
// buffer に収まらない入力は切り詰めず TOO_LONG として弾く.
static t_password_read	read_password_line(int fd, char* buffer, size_t size) {
	size_t	len = 0;
	while (true) {
		char			c;
		const ssize_t	n = read(fd, &c, 1);
		if (n < 0) {
			return PASSWORD_READ_FAILED;
		}
		if (n == 0) {
			if (len == 0) {
				return PASSWORD_READ_EOF;
			}
			break;
		}
		if (c == '\n') {
			break;
		}
		if (len + 1 >= size) {
			return PASSWORD_READ_TOO_LONG;
		}
		buffer[len++] = c;
	}
	buffer[len] = '\0';
	return PASSWORD_READ_OK;
}

// パスワードを取得
const char*	des_acquire_password(const t_master_des* m, char* buffer, size_t size) {
	if (m->pref.password != NULL) {
		return m->pref.password;
	}

	char	prompt[128];
	build_password_prompt(m, prompt, sizeof(prompt));

	// 端末があればそこから読む (メッセージ本体が標準入力を使っている場合があるため).
	// 端末がなければ標準入力にフォールバックする.
	const int	tty_fd = open("/dev/tty", O_RDWR);
	const int	read_fd = (tty_fd >= 0) ? tty_fd : STDIN_FILENO;
	const int	prompt_fd = (tty_fd >= 0) ? tty_fd : STDERR_FILENO;

	// プロンプトが出せなくても読み取りは試みるので, 失敗は無視する
	(void)write_all(prompt_fd, prompt, ft_strlen(prompt));

	// getpass は macOS だと129文字以上の入力をサイレントに切り詰めるので使用を避ける.
	struct termios			saved;
	const bool				muted = mute_tty_echo(read_fd, &saved);
	const t_password_read	result = read_password_line(read_fd, buffer, size);
	if (muted) {
		tcsetattr(read_fd, TCSAFLUSH, &saved);
		// エコーされなかった改行の代わり
		(void)write_all(prompt_fd, "\n", 1);
	}
	if (tty_fd >= 0) {
		close(tty_fd);
	}

	if (result == PASSWORD_READ_TOO_LONG) {
		PRINT_ERROR(&m->master, "password is too long (max %d characters)\n", DES_PASSWORD_MAX_LEN);
		return NULL;
	}
	if (result != PASSWORD_READ_OK) {
		PRINT_ERROR(&m->master, "%s\n", "bad password read");
		return NULL;
	}
	return buffer;
}
