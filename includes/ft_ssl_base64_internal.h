#ifndef FT_SSL_BASE64_INTERNAL_H
#define FT_SSL_BASE64_INTERNAL_H

#include "ft_ssl_lib.h"
#include "ft_ssl_structure.h"

// エンコード入力バッファのサイズ
// 3の倍数にすること
// (3 * 8 = 24 は6の倍数でもあるため, バッファいっぱい分のデータがきっちりエンコードされる)
#define BASE64_ENCODE_INPUT_BUFFFER_SIZE 12288
#define BASE64_ENCODE_OUTPUT_BUFFFER_SIZE 16384

typedef struct s_base64_encode_state
{
	t_elastic_buffer*	input_buffer;

	int out_fd;
	t_elastic_buffer	output_buffer;
} t_base64_encode_state;

typedef struct s_base64_decode_state
{
	t_elastic_buffer*	input_buffer;

	int out_fd;
	t_elastic_buffer	output_buffer;
} t_base64_decode_state;

// [base64 変換コア]
// base64 コマンドと DES の -a オプションで共用する.

// base64_encode.c
void	base64_encode_buffer(t_base64_encode_state* state);
bool	base64_write_lines(int out_fd, const t_elastic_buffer* buffer, size_t line_length);

// base64_decode.c
void	base64_chomp_newline(t_elastic_buffer* buffer);
bool	is_decodable_as_base64(const t_master_base64* m, const t_base64_decode_state* state);
bool	base64_decode_buffer(const t_master_base64* m, t_base64_decode_state* state);

#endif
