#ifndef FT_SSL_BASE64_INTERNAL_H
#define FT_SSL_BASE64_INTERNAL_H

#include "ft_ssl_lib.h"
#include "ft_ssl_structure.h"

// base64 出力の改行幅.
// openssl base64 も openssl enc -a も 64 文字ごとに改行するので, それに合わせる.
#define BASE64_LINE_LENGTH 64

// [base64 変換コア]
// base64 コマンドと DES の -a オプションで共用する.
// どれも「入力(先頭 + 長さ) を受け取り, 結果を elastic_buffer に積む」形に揃えてある.

// base64_encode.c

void	base64_encode_buffer(const void* src, size_t len, t_elastic_buffer* out);
bool	base64_write_lines(int out_fd, const t_elastic_buffer* buffer, size_t line_length);

// base64_decode.c

void	base64_chomp_newline(t_elastic_buffer* buffer);
bool	is_decodable_as_base64(const void* src, size_t len);
bool	base64_decode_buffer(const void* src, size_t len, t_elastic_buffer* out);

#endif
