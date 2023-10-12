#ifndef FT_SSL_BASE64_INTERNAL_H
#define FT_SSL_BASE64_INTERNAL_H

#include "ft_ssl_lib.h"

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

#endif
