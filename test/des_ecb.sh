#!/bin/bash
# test/des_ecb.sh — des-ecb (段階1: 暗号化) を OpenSSL と突き合わせるテスト
#
#   1) 暗号文一致 : ft_ssl enc              == openssl enc
#   2) 往復       : ft_ssl enc | openssl dec == 原文
#
# 前提: プロジェクトルートで ./ft_ssl をビルド済みであること.
#       OpenSSL 3.x では des-ecb が legacy provider にあるため provider を明示する.
# 使い方: bash test/des_ecb.sh

set -u
SSL=./ft_ssl
PROV="-provider legacy -provider default"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# $1: ケース名, $2: 入力ファイル, $3: 鍵(hex; "" も可)
check() {
	local name="$1" infile="$2" key="$3"

	$SSL des-ecb -k "$key" < "$infile" 2>/dev/null > "$TMP/mine"
	openssl enc -des-ecb -K "$key" $PROV < "$infile" 2>/dev/null > "$TMP/ref"

	if ! cmp -s "$TMP/mine" "$TMP/ref"; then
		echo "FAIL [enc]       $name (key='$key')"
		echo "    mine: $(xxd -p "$TMP/mine" | tr -d '\n')"
		echo "    ref : $(xxd -p "$TMP/ref"  | tr -d '\n')"
		fail=$((fail + 1))
		return
	fi

	# ft_ssl の暗号文を openssl で復号し, 原文に戻るか
	openssl enc -d -des-ecb -K "$key" $PROV < "$TMP/mine" 2>/dev/null > "$TMP/back"
	if ! cmp -s "$infile" "$TMP/back"; then
		echo "FAIL [roundtrip] $name (key='$key')"
		fail=$((fail + 1))
		return
	fi

	echo "OK   $name (key='$key')"
	pass=$((pass + 1))
}

# --- 入力データのバリエーション (長さ境界・バイナリ・NUL・改行) ---
printf ''                          > "$TMP/len0"
printf 'A'                         > "$TMP/len1"
printf '1234567'                   > "$TMP/len7"     # 8未満
printf '12345678'                  > "$TMP/len8"     # ブロック境界 (パディングで+1ブロック)
printf '123456789'                 > "$TMP/len9"
printf '123456789012345'           > "$TMP/len15"
printf '1234567890123456'          > "$TMP/len16"    # 2ブロック境界
printf '12345678901234567'         > "$TMP/len17"
head -c 100 /dev/zero | tr '\0' 'x' > "$TMP/len100"
printf '\x00\x00\x00\x00'          > "$TMP/nuls"
printf 'line1\nline2\nline3\n'     > "$TMP/newlines"
printf 'spaces   and\ttabs #!&*()' > "$TMP/special"
# 0x00..0xff の全 256 バイト
i=0
while [ $i -le 255 ]; do
	printf "\\$(printf '%03o' $i)"
	i=$((i + 1))
done > "$TMP/bin256"

# --- 鍵のバリエーション ---
keys=(
	133457799bbcdff1        # 標準テストベクタ鍵
	0000000000000000        # 全ゼロ
	ffffffffffffffff        # 全 f
	0123456789abcdef
	fedcba9876543210
	ff12cd                  # 短い -> ゼロ埋め
	ff1                     # 奇数桁 -> ff10000000000000
	133457799bbcdff10011    # 長い -> 先頭8バイトに切り詰め
)

echo "### 1) 標準鍵 × 各入力長・バイナリ ###"
for f in len0 len1 len7 len8 len9 len15 len16 len17 len100 bin256 nuls newlines special; do
	check "input=$f" "$TMP/$f" 133457799bbcdff1
done

echo
echo "### 2) 鍵バリエーション (代表入力: bin256 / len8) ###"
for k in "${keys[@]}"; do
	check "key bin256" "$TMP/bin256" "$k"
	check "key len8"   "$TMP/len8"   "$k"
done

echo
echo "### 3) 空鍵 (-> 全ゼロ鍵) ###"
check "empty-key len8" "$TMP/len8" ""

echo
echo "=== des-ecb: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]
