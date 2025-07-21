#ifndef FT_SSL_SHA_1_ROUNDS_H
#define FT_SSL_SHA_1_ROUNDS_H

// SHA-1のブロック演算
// S^n(x) (on RFC 3174) is equivalent to ROTL(n, x):
// S^n(X) = (X << n) OR (X >> 32-n).
#define ROTL(n, x) (((x) << (n)) | ((x) >> (SHA_1_WORD_BIT_SIZE - (n))))
#define F(t, b, c, d) \
    ((t < 20) ? ((b & c) | (~b & d)) : \
     (t < 40) ? (b ^ c ^ d) : \
     (t < 60) ? ((b & c) | (b & d) | (c & d)) : \
                (b ^ c ^ d))

#endif
