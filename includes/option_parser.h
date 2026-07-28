#ifndef OPTION_PARSER_H
#define OPTION_PARSER_H

#include "ft_ssl_structure.h"
#include <stddef.h>

// [オプション]

// 本プログラムにおけるオプションのルール:
// 1. 長いオプション(--)は連結を認めない
// 2. 短いのオプション(-)は連結を認める. ただし長いオプション名に一致した場合は連結ではなくオプション名として扱う
// 例:
// - `-pr`は`-p -r`と同じ
// - `-pubout`は`-pubout`と同じ 
// - `-outpub`は`-o -u -t -p -b`と同じ
typedef enum e_option_kind {
	OPTION_SET_TRUE,	// 値を取らず, bool のフィールドを true にする
	OPTION_SET_FALSE,	// 値を取らず, bool のフィールドを false にする
	OPTION_STRING,		// 次の引数を char* のフィールドに入れる
	OPTION_UINT32,		// 次の引数を数値として uint32_t のフィールドに入れる
	OPTION_UINT64,		// 次の引数を数値として uint64_t のフィールドに入れる
	OPTION_CUSTOM,		// 次の引数を handle に渡す (名前から実体を引く場合など)
}	t_option_kind;

// 値の取り方が特殊なオプション用. 失敗時は false を返す (報告は内部で済ませる).
typedef bool	(t_option_handler)(const t_master* master, void* pref, const char* value);

typedef struct s_option_spec {
	const char*			name;			// ハイフンを除いた綴り. 終端は name = NULL
	t_option_kind		kind;
	size_t				field_offset;	// preference 構造体内の位置. offsetof で書く
	uint64_t			min;			// OPTION_UINT32 / OPTION_UINT64 のときの下限
	uint64_t			max;			// 同上, 上限
	t_option_handler*	handle;			// OPTION_CUSTOM のとき使う
}	t_option_spec;

// option_spec.c
// argv の先頭から続くオプションを解析して pref を埋める.
// 戻り値は消費した引数の個数. 解析に失敗したときは -1 (報告は内部で済ませる).
int	parse_options(const t_master* master, char** argv, void* pref, const t_option_spec* specs);

// option_parser.c
int parse_uint32(const t_master* m, const char* str, uint32_t* out, uint32_t min, uint32_t max);
int parse_uint64(const t_master* m, const char* str, uint64_t* out, uint64_t min, uint64_t max);

int parse_number(
	const t_master* m,
	const char* str,
	unsigned long* out,
	unsigned long min,
	unsigned long max
);

#endif
