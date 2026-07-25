#!/bin/bash
# test/des_ecb.sh — des-ecb を OpenSSL と突き合わせるテスト
#
#   [raw]  a) ft_ssl enc        == openssl enc
#          b) openssl dec(ft_ssl enc) == 原文
#          c) ft_ssl dec(openssl enc) == 原文
#   [-a]   d) ft_ssl enc -a     == openssl enc -a
#          e) ft_ssl dec -a(openssl enc -a) == 原文
#   さらに -i/-o のファイル入出力, 不正入力時のエラー終了を確認する.
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

ok()   { echo "OK   $1"; pass=$((pass + 1)); }
ng()   { echo "FAIL $1"; fail=$((fail + 1)); }

# 生バイナリでの暗号文一致・双方向の往復
# $1: ケース名, $2: 入力ファイル, $3: 鍵(hex; "" も可)
check_raw() {
	local name="$1" infile="$2" key="$3"
	local tag="$name (key='$key')"

	$SSL des-ecb -k "$key" < "$infile" 2>/dev/null > "$TMP/mine"
	openssl enc -des-ecb -K "$key" $PROV < "$infile" 2>/dev/null > "$TMP/ref"
	if ! cmp -s "$TMP/mine" "$TMP/ref"; then
		ng "[enc] $tag"
		echo "    mine: $(xxd -p "$TMP/mine" | tr -d '\n')"
		echo "    ref : $(xxd -p "$TMP/ref"  | tr -d '\n')"
		return
	fi

	# ft_ssl の暗号文を openssl で復号
	openssl enc -d -des-ecb -K "$key" $PROV < "$TMP/mine" 2>/dev/null > "$TMP/back"
	if ! cmp -s "$infile" "$TMP/back"; then
		ng "[enc->ossl dec] $tag"
		return
	fi

	# openssl の暗号文を ft_ssl で復号
	$SSL des-ecb -d -k "$key" < "$TMP/ref" 2>/dev/null > "$TMP/back2"
	if ! cmp -s "$infile" "$TMP/back2"; then
		ng "[ossl enc->dec] $tag"
		return
	fi

	ok "raw $tag"
}

# -a (base64) での暗号文一致・往復
# $1: ケース名, $2: 入力ファイル, $3: 鍵(hex)
check_base64() {
	local name="$1" infile="$2" key="$3"
	local tag="$name (key='$key')"

	$SSL des-ecb -a -k "$key" < "$infile" 2>/dev/null > "$TMP/mine64"
	openssl enc -des-ecb -K "$key" -a $PROV < "$infile" 2>/dev/null > "$TMP/ref64"
	if ! cmp -s "$TMP/mine64" "$TMP/ref64"; then
		ng "[enc -a] $tag"
		echo "    mine: $(cat "$TMP/mine64")"
		echo "    ref : $(cat "$TMP/ref64")"
		return
	fi

	$SSL des-ecb -d -a -k "$key" < "$TMP/ref64" 2>/dev/null > "$TMP/back64"
	if ! cmp -s "$infile" "$TMP/back64"; then
		ng "[dec -a] $tag"
		return
	fi

	ok "-a  $tag"
}

# 異常系: 終了ステータスが 0 以外で, かつ期待するエラーメッセージが出ること.
# 終了ステータスだけを見ると, 全機能が壊れて常に 1 を返す状態でも合格してしまうため,
# メッセージまで確認する.
# $1: ケース名, $2: 期待するエラーメッセージ(部分一致), 残り: ft_ssl に渡す引数
#     (標準入力は $TMP/errin から)
check_error() {
	local name="$1" expected="$2"; shift 2
	local err
	err=$($SSL des-ecb "$@" < "$TMP/errin" 2>&1 >/dev/null)
	local rc=$?

	if [ "$rc" -eq 0 ]; then
		ng "[error expected] $name (exit=0)"
		return
	fi
	case "$err" in
		*"$expected"*)
			ok "error $name"
			;;
		*)
			ng "[message] $name"
			echo "    expected: *$expected*"
			echo "    actual  : $(echo "$err" | grep -v '\[D\]' | tail -1)"
			;;
	esac
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
head -c 200 /dev/zero | tr '\0' 'z' > "$TMP/len200"  # base64 が複数行になる長さ
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

inputs="len0 len1 len7 len8 len9 len15 len16 len17 len100 len200 bin256 nuls newlines special"

echo "### 1) 標準鍵 × 各入力長・バイナリ (raw) ###"
for f in $inputs; do
	check_raw "input=$f" "$TMP/$f" 133457799bbcdff1
done

echo
echo "### 2) 標準鍵 × 各入力長・バイナリ (-a base64) ###"
for f in $inputs; do
	check_base64 "input=$f" "$TMP/$f" 133457799bbcdff1
done

echo
echo "### 3) 鍵バリエーション (代表入力: bin256 / len8) ###"
for k in "${keys[@]}"; do
	check_raw "key bin256" "$TMP/bin256" "$k"
	check_raw "key len8"   "$TMP/len8"   "$k"
done

echo
echo "### 4) 空鍵 (-> 全ゼロ鍵) ###"
check_raw "empty-key len8" "$TMP/len8" ""

echo
echo "### 5) -i / -o によるファイル入出力 ###"
KEY=133457799bbcdff1
$SSL des-ecb -k $KEY -i "$TMP/bin256" -o "$TMP/io_enc" 2>/dev/null
openssl enc -des-ecb -K $KEY $PROV -in "$TMP/bin256" -out "$TMP/io_ref" 2>/dev/null
cmp -s "$TMP/io_enc" "$TMP/io_ref" && ok "-i/-o enc" || ng "-i/-o enc"
$SSL des-ecb -d -k $KEY -i "$TMP/io_enc" -o "$TMP/io_back" 2>/dev/null
cmp -s "$TMP/bin256" "$TMP/io_back" && ok "-i/-o dec" || ng "-i/-o dec"

echo
echo "### 6) base64 入力の空白・改行の許容 ###"
# openssl の -a 出力は 64 文字ごとに改行される. さらに空白を挿入しても復号できること.
openssl enc -des-ecb -K $KEY -a $PROV < "$TMP/len200" 2>/dev/null > "$TMP/ws64"
$SSL des-ecb -d -a -k $KEY < "$TMP/ws64" 2>/dev/null > "$TMP/ws_back"
cmp -s "$TMP/len200" "$TMP/ws_back" && ok "multi-line base64" || ng "multi-line base64"
tr -d '\n' < "$TMP/ws64" > "$TMP/ws_flat"
$SSL des-ecb -d -a -k $KEY < "$TMP/ws_flat" 2>/dev/null > "$TMP/ws_back2"
cmp -s "$TMP/len200" "$TMP/ws_back2" && ok "single-line base64" || ng "single-line base64"

echo
echo "### 7) 異常系 ###"
# 8 の倍数でない暗号文
printf 'abc' > "$TMP/errin"
check_error "decrypt: length not multiple of 8" "bad decrypt: wrong final block length" -d -k $KEY
# 空の暗号文
printf '' > "$TMP/errin"
check_error "decrypt: empty input" "bad decrypt: wrong final block length" -d -k $KEY
# パディングが壊れた暗号文 (ゼロ 16 バイトを別鍵で復号)
head -c 16 /dev/zero > "$TMP/errin"
check_error "decrypt: bad padding" "bad decrypt" -d -k 0123456789abcdef
# base64 として不正な入力
printf 'not*valid*base64!!' > "$TMP/errin"
check_error "decrypt -a: invalid base64" "error reading input file" -d -a -k $KEY
# 鍵未指定
printf 'x' > "$TMP/errin"
check_error "no key" "key is required (-k)" -e
# 未知のオプション
check_error "unknown option" "illegal option -- Z" -Z -k $KEY

echo
echo "=== des-ecb: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]
