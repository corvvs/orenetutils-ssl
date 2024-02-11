#ifndef FT_SSL_STRUCTURE_H
#define FT_SSL_STRUCTURE_H

#include "common.h"
#include "generic_message.h"

typedef struct s_message
{
	bool is_bytestream;
	const char *file_path; // これが NULL かつ is_bytestream が true のときは stdin とみなす
	u_int8_t *message;
	size_t message_bit_len;
} t_message;

typedef	void				(generic_hash_function)(t_generic_message* result, const t_generic_message* text);
typedef t_generic_message	(hmac_function)(const t_generic_message *key, const t_generic_message *text);
typedef	t_generic_message	(pseudo_random_function)(const t_generic_message* arg1, const t_generic_message* arg2);

typedef struct s_hash_algorithm {
	const char*				name;
	generic_hash_function*	func;
	size_t					block_byte_size;
	size_t					hash_byte_size;
}	t_hash_algorithm;

typedef struct s_hmac_hash_interface {
	const char*			name;
	t_hash_algorithm	algorithm;
	t_generic_message	ipad;
	t_generic_message	opad;
}	t_hmac_hash_interface;

typedef struct s_pbkdf2_prf {
	const char*				name;
	pseudo_random_function*	func;
	size_t					hlen;
}	t_pbkdf2_prf;

// TODO: サブコマンドごとの構造体に分けること
typedef struct s_preference {
	bool	is_echo;			// -p option	for hashes
	bool	is_quiet;			// -q option	for hashes
	bool	is_reverse;			// -r option	for hashes
	char*	message_argument;	// -s option	for hashes, -S for pbkdf2
	
	// generic
	char*	path_input;			// -i option
	char*	path_output;		// -o option
	bool	is_decode;			// -e/-d option

	// for base64
	// for hmac
	char*	path_key;			// -k
	t_hmac_hash_interface*	hi;	// -a
	// for pbkdf2
	char*	path_salt;			// -s
	t_pbkdf2_prf*		prf;	// -a
	uint32_t	stretch;		// -c; stretch count
	uint64_t	dklen;			// -l; derived key length
	// for des
	bool	is_base64;			// -a option; true の場合, 入出力をbase64でデコード/エンコードする
	char*	message_key;		// -k option; ブロック鍵; 64ビット in 16進数
	char*	message_passphrase;	// -p option; パスフレーズ
	char*	message_salt;		// -s option; KDFのソルト; 64ビット in 16進数
	char*	message_iv;			// -v option; 初期化ベクトル; 64ビット in 16進数
}	t_preference;

typedef enum e_command {
	COMMAND_MD5,
	COMMAND_SHA224,
	COMMAND_SHA256,
	COMMAND_SHA384,
	COMMAND_SHA512,
	COMMAND_SHA512_224,
	COMMAND_SHA512_256,
	COMMAND_UNKNOWN
}	t_command;

struct s_master;

typedef int (t_runner_func)(struct s_master *master, char **);

typedef struct e_command_pair {
	const char* 	name;
	t_runner_func*	func;
}	t_command_pair;

#define DEF_COMMAND_PAIR(n, f) (t_command_pair){ .name = n, .func = f }

typedef struct s_master {
	const char*		program_name;
	t_command_pair	command;
	const char*		command_name;

	bool				in_repl;
	t_elastic_buffer	repl;
	bool				stdin_eof_reached;
}	t_master;

typedef struct s_master_digest {
	t_master		master;
	t_preference	pref;
}	t_master_digest;

typedef struct s_master_base64 {
	t_master		master;
	t_preference	pref;
}	t_master_base64;

typedef struct s_master_hmac {
	t_master		master;
	t_preference	pref;
}	t_master_hmac;

typedef struct s_master_pbkdf2 {
	t_master		master;
	t_preference	pref;
}	t_master_pbkdf2;

typedef struct s_master_des {
	t_master		master;
	t_preference	pref;
}	t_master_des;


#endif
