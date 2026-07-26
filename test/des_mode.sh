#!/bin/bash
# test/des_mode.sh — des-* の各モードを OpenSSL と突き合わせるテスト
#
#   [raw]  a) ft_ssl enc        == openssl enc
#          b) openssl dec(ft_ssl enc) == 原文
#          c) ft_ssl dec(openssl enc) == 原文
#   [-a]   d) ft_ssl enc -a     == openssl enc -a
#          e) ft_ssl dec -a(openssl enc -a) == 原文
#   さらに -i/-o のファイル入出力, 不正入力時のエラー終了を確認する.
#
# 前提: プロジェクトルートで ./ft_ssl をビルド済みであること.
#       OpenSSL 3.x では des-* が legacy provider にあるため provider を明示する.
#
# 使い方: bash test/des_mode.sh <ft_sslのコマンド名> <opensslのコマンド名> [IV(hex)]
#   bash test/des_mode.sh des-ecb  des-ecb
#   bash test/des_mode.sh des-cbc  des-cbc      0011223344556677
#   bash test/des_mode.sh des3-ecb des-ede3-ecb
#   bash test/des_mode.sh des3-cbc des-ede3-cbc 0011223344556677
#
# 3DES は ft_ssl と openssl でコマンド名が違う (des3-cbc / des-ede3-cbc) ため別々に渡す.
# IV を渡すと ft_ssl には -v, openssl には -iv として与える.

set -u
CMD=${1:?usage: des_mode.sh <ft_ssl-command> <openssl-command> [iv-hex]}
OSSL_CMD=${2:?usage: des_mode.sh <ft_ssl-command> <openssl-command> [iv-hex]}
IV=${3:-}

SSL=./ft_ssl
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# デバッグ出力抑制フラグ
export FT_SSL_DEBUG=0

# OpenSSL 3.x では des-* が legacy provider にあるため provider を明示しないと使えない.
# 一方 1.1.1 には -provider 自体が無く, 付けるとエラーになる.
# どちらの環境でも動くように, 実際に試して決める.
if openssl enc -des-ecb -K 0011223344556677 -provider legacy -provider default \
		-in /dev/null >/dev/null 2>&1; then
	PROV="-provider legacy -provider default"
else
	PROV=""
fi

# ft_ssl 側と openssl 側で IV オプションの綴りが違う.
# bash 3.2 では set -u 下の空配列展開が落ちるので, 配列ではなく文字列で持ち
# 非クォートで展開する (IV は 16 進文字列なので単語分割の心配はない).
SSL_IV=""
OSSL_IV=""
if [ -n "$IV" ]; then
	SSL_IV="-v $IV"
	OSSL_IV="-iv $IV"
fi

# パディングするモードかどうかを openssl の実挙動から判定する.
# (自分の実装から判定すると, 実装が間違っていてもテストが追随してしまう)
printf 'x' > "$TMP/probe"
if [ "$(openssl enc -"$OSSL_CMD" -K 133457799bbcdff1 $OSSL_IV $PROV < "$TMP/probe" 2>/dev/null | wc -c)" -eq 1 ]; then
	PADS=0   # ストリームモード: 暗号文長 = 平文長
else
	PADS=1   # ブロックモード
fi

pass=0
fail=0

ok()   { echo "OK   $1"; pass=$((pass + 1)); }
ng()   { echo "FAIL $1"; fail=$((fail + 1)); }

# 生バイナリでの暗号文一致・双方向の往復
# $1: ケース名, $2: 入力ファイル, $3: 鍵(hex; "" も可)
check_raw() {
	local name="$1" infile="$2" key="$3"
	local tag="$name (key='$key')"

	$SSL "$CMD" -k "$key" $SSL_IV < "$infile" 2>/dev/null > "$TMP/mine"
	openssl enc -"$OSSL_CMD" -K "$key" $OSSL_IV $PROV < "$infile" 2>/dev/null > "$TMP/ref"
	if ! cmp -s "$TMP/mine" "$TMP/ref"; then
		ng "[enc] $tag"
		echo "    mine: $(xxd -p "$TMP/mine" | tr -d '\n')"
		echo "    ref : $(xxd -p "$TMP/ref"  | tr -d '\n')"
		return
	fi

	# ft_ssl の暗号文を openssl で復号
	openssl enc -d -"$OSSL_CMD" -K "$key" $OSSL_IV $PROV < "$TMP/mine" 2>/dev/null > "$TMP/back"
	if ! cmp -s "$infile" "$TMP/back"; then
		ng "[enc->ossl dec] $tag"
		return
	fi

	# openssl の暗号文を ft_ssl で復号
	$SSL "$CMD" -d -k "$key" $SSL_IV < "$TMP/ref" 2>/dev/null > "$TMP/back2"
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

	$SSL "$CMD" -a -k "$key" $SSL_IV < "$infile" 2>/dev/null > "$TMP/mine64"
	openssl enc -"$OSSL_CMD" -K "$key" $OSSL_IV -a $PROV < "$infile" 2>/dev/null > "$TMP/ref64"
	if ! cmp -s "$TMP/mine64" "$TMP/ref64"; then
		ng "[enc -a] $tag"
		echo "    mine: $(cat "$TMP/mine64")"
		echo "    ref : $(cat "$TMP/ref64")"
		return
	fi

	$SSL "$CMD" -d -a -k "$key" $SSL_IV < "$TMP/ref64" 2>/dev/null > "$TMP/back64"
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
	err=$($SSL "$CMD" "$@" < "$TMP/errin" 2>&1 >/dev/null)
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
	0123456789abcdef23456789abcdef01456789abcdef0123    # 24バイト (3DES 用; DES では先頭8バイト)
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
$SSL "$CMD" -k $KEY $SSL_IV -i "$TMP/bin256" -o "$TMP/io_enc" 2>/dev/null
openssl enc -"$OSSL_CMD" -K $KEY $OSSL_IV $PROV -in "$TMP/bin256" -out "$TMP/io_ref" 2>/dev/null
cmp -s "$TMP/io_enc" "$TMP/io_ref" && ok "-i/-o enc" || ng "-i/-o enc"
$SSL "$CMD" -d -k $KEY $SSL_IV -i "$TMP/io_enc" -o "$TMP/io_back" 2>/dev/null
cmp -s "$TMP/bin256" "$TMP/io_back" && ok "-i/-o dec" || ng "-i/-o dec"

echo
echo "### 6) base64 入力の空白・改行の許容 ###"
# openssl の -a 出力は 64 文字ごとに改行される. さらに空白を挿入しても復号できること.
openssl enc -"$OSSL_CMD" -K $KEY $OSSL_IV -a $PROV < "$TMP/len200" 2>/dev/null > "$TMP/ws64"
$SSL "$CMD" -d -a -k $KEY $SSL_IV < "$TMP/ws64" 2>/dev/null > "$TMP/ws_back"
cmp -s "$TMP/len200" "$TMP/ws_back" && ok "multi-line base64" || ng "multi-line base64"
tr -d '\n' < "$TMP/ws64" > "$TMP/ws_flat"
$SSL "$CMD" -d -a -k $KEY $SSL_IV < "$TMP/ws_flat" 2>/dev/null > "$TMP/ws_back2"
cmp -s "$TMP/len200" "$TMP/ws_back2" && ok "single-line base64" || ng "single-line base64"

echo
echo "### 7) パスワードからの鍵導出 (-p / -s) ###"
PW="MySuperSecurePassword"
SALT=0011223344556677

# -S 指定時に "Salted__" ヘッダを付けるかは OpenSSL のバージョンで違う
# (1.1.1 は付け, 3.x は付けない). ft_ssl は 1.1.1 に合わせているので,
# 参照側がどちらなのかを実挙動から判定して期待値を変える.
printf 'x' > "$TMP/probe"
openssl enc -"$OSSL_CMD" -pass pass:pw -S $SALT -pbkdf2 $OSSL_IV $PROV < "$TMP/probe" 2>/dev/null > "$TMP/probe.out"
if [ "$(head -c 8 "$TMP/probe.out")" = "Salted__" ]; then
	REF_SALTS_HEADER=1   # 1.1.1 系: バイト一致を期待できる
	echo "  (参照 openssl は -S 指定時にヘッダを付ける = 1.1.1 系)"
else
	REF_SALTS_HEADER=0   # 3.x 系: バイト一致しないので復号可否で検証する
	echo "  (参照 openssl は -S 指定時にヘッダを付けない = 3.x 系)"
fi

for f in len0 len8 len17 bin256; do
	$SSL "$CMD" -p "$PW" -s $SALT $SSL_IV < "$TMP/$f" 2>/dev/null > "$TMP/pw_mine"
	openssl enc -"$OSSL_CMD" -pass pass:"$PW" -S $SALT -pbkdf2 $OSSL_IV $PROV < "$TMP/$f" 2>/dev/null > "$TMP/pw_ref"

	if [ "$REF_SALTS_HEADER" -eq 1 ]; then
		# 同じ形式なので暗号文がバイト一致するはず
		if cmp -s "$TMP/pw_mine" "$TMP/pw_ref"; then
			ok "-p -s enc input=$f (byte-exact)"
		else
			ng "[-p -s enc] input=$f"
			echo "    mine: $(xxd -p "$TMP/pw_mine" | tr -d '\n')"
			echo "    ref : $(xxd -p "$TMP/pw_ref"  | tr -d '\n')"
		fi
	else
		# 形式が違うのでバイト比較はできない.
		# ft_ssl の出力はヘッダを持つので, 参照側は -S を省けば復号できるはず.
		openssl enc -d -"$OSSL_CMD" -pass pass:"$PW" -pbkdf2 $OSSL_IV $PROV < "$TMP/pw_mine" 2>/dev/null > "$TMP/pw_o_dec"
		cmp -s "$TMP/$f" "$TMP/pw_o_dec" \
			&& ok "-p -s enc input=$f (3.x が -S 省略で復号できる)" \
			|| ng "[-p -s enc] input=$f (3.x が復号できない)"
	fi

	# openssl の暗号文を ft_ssl で復号 (ヘッダ有無どちらも受理できること)
	$SSL "$CMD" -d -p "$PW" -s $SALT $SSL_IV < "$TMP/pw_ref" 2>/dev/null > "$TMP/pw_back"
	cmp -s "$TMP/$f" "$TMP/pw_back" && ok "-p -s dec input=$f" || ng "[-p -s dec] input=$f"
done

# -s 指定時にも ft_ssl は必ずヘッダを付ける (1.1.1 準拠)
$SSL "$CMD" -p "$PW" -s $SALT $SSL_IV < "$TMP/len17" 2>/dev/null > "$TMP/pw_s_hdr"
[ "$(head -c 8 "$TMP/pw_s_hdr")" = "Salted__" ] \
	&& ok "-p -s: Salted__ ヘッダを付ける (1.1.1 準拠)" \
	|| ng "[-p -s] Salted__ ヘッダがない"

# -s なしでは salt が毎回変わるので, 暗号文の一致ではなく往復で確認する.
# 先頭には "Salted__" + salt が付く.
$SSL "$CMD" -p "$PW" $SSL_IV < "$TMP/len17" 2>/dev/null > "$TMP/pw_salted"
if [ "$(head -c 8 "$TMP/pw_salted")" = "Salted__" ]; then
	ok "-p (no -s): Salted__ ヘッダが付く"
else
	ng "[-p (no -s)] Salted__ ヘッダがない"
fi
# 2 回暗号化すると salt が変わるので結果も変わる
$SSL "$CMD" -p "$PW" $SSL_IV < "$TMP/len17" 2>/dev/null > "$TMP/pw_salted2"
cmp -s "$TMP/pw_salted" "$TMP/pw_salted2" && ng "[-p (no -s)] salt が毎回同じ" || ok "-p (no -s): salt が毎回変わる"

# ft_ssl -> openssl
openssl enc -d -"$OSSL_CMD" -pass pass:"$PW" -pbkdf2 $OSSL_IV $PROV < "$TMP/pw_salted" 2>/dev/null > "$TMP/pw_o_back"
cmp -s "$TMP/len17" "$TMP/pw_o_back" && ok "-p enc -> openssl dec" || ng "[-p enc -> openssl dec]"
# openssl -> ft_ssl
openssl enc -"$OSSL_CMD" -pass pass:"$PW" -pbkdf2 $OSSL_IV $PROV < "$TMP/len17" 2>/dev/null > "$TMP/pw_o_enc"
$SSL "$CMD" -d -p "$PW" $SSL_IV < "$TMP/pw_o_enc" 2>/dev/null > "$TMP/pw_m_back"
cmp -s "$TMP/len17" "$TMP/pw_m_back" && ok "openssl enc -> -p dec" || ng "[openssl enc -> -p dec]"

# -a と併用 (Salted__ ヘッダは base64 の内側)
$SSL "$CMD" -a -p "$PW" $SSL_IV < "$TMP/len17" 2>/dev/null > "$TMP/pw_a"
openssl enc -d -"$OSSL_CMD" -a -pass pass:"$PW" -pbkdf2 $OSSL_IV $PROV < "$TMP/pw_a" 2>/dev/null > "$TMP/pw_a_back"
cmp -s "$TMP/len17" "$TMP/pw_a_back" && ok "-a -p enc -> openssl dec" || ng "[-a -p enc -> openssl dec]"

echo
echo "### 8) 異常系 ###"
if [ "$PADS" -eq 1 ]; then
	# 8 の倍数でない暗号文
	printf 'abc' > "$TMP/errin"
	check_error "decrypt: length not multiple of 8" "bad decrypt: wrong final block length" -d -k $KEY $SSL_IV
	# 空の暗号文
	printf '' > "$TMP/errin"
	check_error "decrypt: empty input" "bad decrypt: wrong final block length" -d -k $KEY $SSL_IV
	# パディングが壊れた暗号文 (ゼロ 16 バイトを別鍵で復号)
	head -c 16 /dev/zero > "$TMP/errin"
	check_error "decrypt: bad padding" "bad decrypt" -d -k 0123456789abcdef $SSL_IV
fi
# base64 として不正な入力
printf 'not*valid*base64!!' > "$TMP/errin"
check_error "decrypt -a: invalid base64" "bad decrypt" -d -a -k $KEY $SSL_IV
# 未知のオプション
printf 'x' > "$TMP/errin"
check_error "unknown option" "illegal option -- Z" -Z -k $KEY $SSL_IV
# 鍵を直接もらっているのに IV だけ足りない (パスワードもない)
if [ -n "$IV" ]; then
	check_error "key without iv" "iv undefined" -e -k $KEY
fi
# パスワード復号で salt が得られない (ヘッダなし・-s なし)
head -c 16 /dev/zero > "$TMP/errin"
check_error "decrypt: no salt" "bad magic number" -d -p pw $SSL_IV
# IV を使うモードで -v 未指定 (OpenSSL の "iv undefined" 相当)
if [ -n "$IV" ]; then
	check_error "no iv" "iv undefined" -e -k $KEY
fi

echo
echo "=== $CMD: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]
