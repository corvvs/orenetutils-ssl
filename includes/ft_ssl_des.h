#ifndef FT_SSL_DES_H
#define FT_SSL_DES_H

#include "ft_ssl_structure.h"

// DES ブロック長
#define DES_BLOCK_BYTE_LEN 8
// DES 初期化ベクトル長
#define DES_IV_BYTE_LEN DES_BLOCK_BYTE_LEN
// DES ソルト長; 本来ソルトの長さはなんでもいいのだが, 歴史的経緯により長さが決まっている?
#define DES_SALT_BYTE_LEN DES_BLOCK_BYTE_LEN
// DES ブロック鍵長
#define DES_BLOCK_KEY_BYTE_LEN 8
// DES 受付鍵長
#define DES_KEY_BYTE_LEN DES_BLOCK_KEY_BYTE_LEN
// トリプルDES 受付鍵長
#define DES3_KEY_BYTE_LEN (DES_BLOCK_KEY_BYTE_LEN * 3)
// DES ラウンド鍵長
#define DES_ROUND_KEY_BYTE_LEN 6
// DES ラウンド数
#define DES_ROUND_NUMBER 16

// DES ラウンド鍵
typedef struct	s_des_round_keys {
	// 48bit ずつのラウンド鍵
	uint64_t	keys[DES_ROUND_NUMBER];
}	t_des_round_keys;

// DES ブロック処理
typedef uint64_t			(t_des_block_proc)(uint64_t, const t_des_round_keys* round_keys);

// DES フロー処理
typedef t_generic_message	(t_des_flow_proc)(const t_master* master, const t_generic_message* flow_input);

typedef struct	s_des_parameters {
	uint64_t	block_key;
	uint64_t	salt;
	uint64_t	initialize_vector;
}	t_des_parameters;

// DES ブロック定義
typedef struct	s_des_block_def {
	t_des_block_proc*	block_proc;
	t_des_round_keys*	round_keys;
	// 鍵の系統の数; DES -> 1, 3DES -> 3
	unsigned int		key_number;
}	t_des_block_def;

int	parse_options_des(const t_master* master, char** argv, t_preference* pref_ptr);

// DES 置換関数群

uint64_t	des_elemental_ip(uint64_t block_input);
uint64_t	des_elemental_fp(uint64_t block_input);
uint64_t	des_key_permutation_1(uint64_t master_key);
uint64_t	des_key_permutation_2(uint64_t master_key);
uint64_t	des_feistel_ep(uint64_t master_key);
uint32_t	des_feistel_p(uint32_t master_key);

// DES 鍵スケジュール
t_des_round_keys	des_key_schedule(uint64_t master_key);

uint32_t	des_elemental_feistel(uint32_t rightside, uint64_t round_key);


// DES ブロック処理
// すべて t_des_block_proc 型であること

// シングルDES 暗号化
uint64_t	des_be1(uint64_t block_input, const t_des_round_keys* round_keys);
// シングルDES 復号
uint64_t	des_bd1(uint64_t block_input, const t_des_round_keys* round_keys);
// トリプルDES 暗号化
uint64_t	des_be3(uint64_t block_input, const t_des_round_keys* round_keys);
// トリプルDES 復号
uint64_t	des_bd3(uint64_t block_input, const t_des_round_keys* round_keys);

// DES フロー処理
// すべて t_des_flow_proc 型であること

// t_generic_message	des_flow_ecb(const t_master* master, const t_generic_message* flow_input);
// t_generic_message	des_flow_cbc(const t_master* master, const t_generic_message* flow_input);
// t_generic_message	des_flow_pcbc(const t_master* master, const t_generic_message* flow_input);
// t_generic_message	des_flow_cfb(const t_master* master, const t_generic_message* flow_input);
// t_generic_message	des_flow_ofb(const t_master* master, const t_generic_message* flow_input);
// t_generic_message	des_flow_ctr(const t_master* master, const t_generic_message* flow_input);

// DES サブコマンド群

int	run_des_ecb(t_master* master, char **argv);
int	run_des_cbc(t_master* master, char **argv);
int	run_des_cfb(t_master* master, char **argv);
int	run_des_ofb(t_master* master, char **argv);
int	run_des_pcbc(t_master* master, char **argv);
int	run_des3_ecb(t_master* master, char **argv);
int	run_des3_cbc(t_master* master, char **argv);
int	run_des3_cfb(t_master* master, char **argv);

#endif
