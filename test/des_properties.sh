#!/bin/bash
# test/des_properties.sh — DES が規格上満たすべき性質の確認
#
# des_mode.sh が「OpenSSL と同じ答えを出すか」を見るのに対し, こちらは
# 実装同士を突き合わせなくても成り立つはずの性質を直接確かめる.
# 鍵スケジュールやカウンタの扱いを間違えるとここで落ちる.
#
#   1. 鍵のパリティビット (各バイトの最下位ビット) は使われない
#   2. 弱鍵では暗号化が対合になる     E_K(E_K(x)) = x
#   3. 準弱鍵の対では互いに打ち消し合う E_K1(E_K2(x)) = x
#   4. 3DES に同じ鍵を3本与えると単一 DES と一致する
#   5. CTR のカウンタは 2^64 で巻き戻る
#   6. 乱数取得は同一プロセス内で繰り返し呼んでも毎回違う値を返す
#
# 前提: プロジェクトルートで ./ft_ssl をビルド済みであること.
# 使い方: bash test/des_properties.sh

set -u
SSL=./ft_ssl
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# デバッグ出力抑制フラグ
export FT_SSL_DEBUG=0

pass=0
fail=0

expect() { # expect <名前> <実際> <期待>
	if [ "$2" = "$3" ]; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		echo "  FAIL [$1]"
		echo "        実際: $2"
		echo "        期待: $3"
	fi
}

# 16進文字列をそのままのバイト列としてファイルに書く
write_hex() { # write_hex <16進文字列> <出力先>
	ruby -e 'STDOUT.binmode; STDOUT.write([ARGV[0]].pack("H*"))' "$1" > "$2"
}

# 1ブロック (8バイト) を ECB で暗号化し, 結果を16進で返す.
# パディングありなので出力は E(平文) || E(パディングブロック) の16バイトになる.
# 先頭8バイトが求める E(平文) そのもの.
encrypt_block() { # encrypt_block <鍵の16進> <平文の16進>
	write_hex "$2" "$TMP/pt"
	"$SSL" des-ecb -k "$1" -i "$TMP/pt" 2>/dev/null | head -c 8 | od -An -tx1 | tr -d ' \n'
}

PLAIN=0123456789abcdef

echo "--- 1. パリティビットは鍵として使われない ---"
# 各バイトの最下位ビットだけが違う鍵は, 同じ鍵として扱われなければならない
base=$(encrypt_block 0000000000000000 $PLAIN)
expect "00.. と 01.. が同じ鍵になる" "$(encrypt_block 0101010101010101 $PLAIN)" "$base"
base=$(encrypt_block 133457799bbcdff1 $PLAIN)
expect "既知の鍵の最下位ビットを反転" "$(encrypt_block 123456789abcdef0 $PLAIN)" "$base"

echo "--- 2. 弱鍵では暗号化が対合になる ---"
for k in 0101010101010101 fefefefefefefefe e0e0e0e0f1f1f1f1 1f1f1f1f0e0e0e0e; do
	once=$(encrypt_block "$k" "$PLAIN")
	expect "弱鍵 $k で2回かけると戻る" "$(encrypt_block "$k" "$once")" "$PLAIN"
done

echo "--- 3. 準弱鍵の対は互いを打ち消す ---"
semi_weak_pairs="
01fe01fe01fe01fe:fe01fe01fe01fe01
1fe01fe00ef10ef1:e01fe01ff10ef10e
01e001e001f101f1:e001e001f101f101
1ffe1ffe0efe0efe:fe1ffe1ffe0efe0e
011f011f010e010e:1f011f010e010e01
e0fee0fef1fef1fe:fee0fee0fef1fef1
"
for pair in $semi_weak_pairs; do
	k1=${pair%%:*}
	k2=${pair##*:}
	once=$(encrypt_block "$k2" "$PLAIN")
	expect "準弱鍵 $k1 / $k2" "$(encrypt_block "$k1" "$once")" "$PLAIN"
done

echo "--- 4. 3DES に同じ鍵を3本与えると単一 DES と一致する ---"
# EDE なので K1=K2=K3 のとき E(D(E(x))) = E(x) になる
head -c 64 /dev/urandom > "$TMP/msg"
K=0123456789abcdef
single=$("$SSL" des-ecb  -k "$K"       -i "$TMP/msg" | od -An -tx1 | tr -d ' \n')
triple=$("$SSL" des3-ecb -k "$K$K$K"   -i "$TMP/msg" | od -An -tx1 | tr -d ' \n')
expect "des3-ecb(K,K,K) == des-ecb(K)" "$triple" "$single"
single=$("$SSL" des-cbc  -k "$K"     -v 0011223344556677 -i "$TMP/msg" | od -An -tx1 | tr -d ' \n')
triple=$("$SSL" des3-cbc -k "$K$K$K" -v 0011223344556677 -i "$TMP/msg" | od -An -tx1 | tr -d ' \n')
expect "des3-cbc(K,K,K) == des-cbc(K)" "$triple" "$single"

echo "--- 5. CTR のカウンタは 2^64 で巻き戻る ---"
# 初期カウンタを最大値にして2ブロック流すと,
# 2ブロック目の鍵ストリームはカウンタ 0 のものになるはず
head -c 16 /dev/zero > "$TMP/zero16"
actual=$("$SSL" des-ctr -k "$K" -v ffffffffffffffff -i "$TMP/zero16" | od -An -tx1 | tr -d ' \n')
# 平文が全 0 なので, 出力はそのまま鍵ストリーム E(カウンタ) になる
expected="$(encrypt_block "$K" ffffffffffffffff)$(encrypt_block "$K" 0000000000000000)"
expect "カウンタ ffffffffffffffff の次が 0 になる" "$actual" "$expected"

echo "--- 6. 乱数取得は同一プロセス内で繰り返しても毎回変わる ---"
# random_bytes (srcs/utils_random.c) は /dev/urandom の fd を開いたまま使い回す.
# REPL は 1 プロセスで複数コマンドを走らせるので, 2 回目以降も正しく読めているかを
# ここで確かめる. des_mode.sh の同種の検査はプロセスを分けて呼ぶため, この経路は通らない.
# salt は "Salted__"(8) の直後の 8 バイト.
salt_of() { # salt_of <暗号文ファイル>
	head -c 16 "$1" | tail -c 8 | od -An -tx1 | tr -d ' \n'
}
# salt_of は改行を付けないので, 数え上げる側で行に分ける.
# (付けないまま sort -u に渡すと全部が 1 行に繋がり, 常に「1 種」になって素通りする)
count_distinct_salts() { # count_distinct_salts <暗号文ファイル...>
	for f in "$@"; do
		salt_of "$f"
		echo
	done | sort -u | wc -l | tr -d ' '
}
write_hex "$PLAIN" "$TMP/msg8"
for i in 1 2 3; do echo "des-ecb -p pw -i $TMP/msg8 -o $TMP/salt_run$i"; done \
	| "$SSL" >/dev/null 2>&1
expect "REPL 内 3 回で salt が 3 種" \
	"$(count_distinct_salts "$TMP/salt_run1" "$TMP/salt_run2" "$TMP/salt_run3")" "3"
# 全ゼロなら, open の失敗を見逃して未初期化のまま進んでいる疑いがある
expect "salt が全ゼロでない" \
	"$([ "$(salt_of "$TMP/salt_run1")" = "0000000000000000" ] && echo zero || echo nonzero)" "nonzero"
# 陰性対照: -s で salt を固定すれば 3 回とも一致する.
# (これが 3 種になるなら, 上の検査は salt ではない何かを見ている)
for i in 1 2 3; do echo "des-ecb -p pw -s 8877665544332211 -i $TMP/msg8 -o $TMP/fixed_run$i"; done \
	| "$SSL" >/dev/null 2>&1
expect "陰性対照: -s 指定なら 1 種" \
	"$(count_distinct_salts "$TMP/fixed_run1" "$TMP/fixed_run2" "$TMP/fixed_run3")" "1"
expect "陰性対照: -s の値がそのまま入る" "$(salt_of "$TMP/fixed_run1")" "8877665544332211"

echo
echo "=== des_properties: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]
