#!/bin/bash
# test/options.sh — オプション解析の規則の確認
#
# オプションは includes/option_parser.h の表 (t_option_spec) で定義し,
# 共通の parse_options() が解析する. その規則をここで固定する.
#
#   1. "-name" は綴り全体を名前として引く (1文字でも複数文字でも同じ経路)
#   2. 引けなければ1文字ずつに分解し, 全文字が表にあるときだけ連結として通す
#   3. "--name" は名前として引くだけで, 連結にはしない
#   4. 値を取るオプションは連結の末尾でなければならない
#   5. 弾くときは1文字ずつ見た結果ではなく, 元の綴りを添える
#
# 連結 (2) は openssl には無い (1.1.1w は `dgst -md5 -rc` を Unrecognized flag rc として
# 弾く). openssl が受ける入力の解釈は変えずに上乗せしている, という位置づけ.
#
# 前提: プロジェクトルートで ./ft_ssl をビルド済みであること.
# 使い方: bash test/options.sh

set -u
SSL=./ft_ssl
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# デバッグ出力抑制フラグ
export FT_SSL_DEBUG=0

pass=0
fail=0

MD5_ABC=900150983cd24fb0d6963f7d28e17f72

printf 'abc'  > "$TMP/in"
printf 'k'    > "$TMP/key"
printf 'YWJj' > "$TMP/b64"   # "abc" を base64 にしたもの

# 標準出力が期待どおりで, かつ成功終了することを確かめる
expect_out() { # expect_out <名前> <期待する標準出力> <ft_ssl に渡す引数...>
	local name=$1 want=$2
	shift 2
	local got rc
	got=$("$SSL" "$@" < /dev/null 2>/dev/null)
	rc=$?
	if [ "$rc" -ne 0 ]; then
		fail=$((fail + 1))
		echo "  FAIL [$name] 失敗した (exit=$rc)"
	elif [ "$got" = "$want" ]; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		echo "  FAIL [$name]"
		echo "        実際: [$got]"
		echo "        期待: [$want]"
	fi
}

# エラーで終わり, かつ期待する文言を出すことを確かめる.
# 終了コードも見るので「エラーを出しながら成功扱いする」退行も捕まえられる.
expect_err() { # expect_err <名前> <エラーに含まれるべき文字列> <ft_ssl に渡す引数...>
	local name=$1 want=$2
	shift 2
	local err rc
	err=$("$SSL" "$@" < /dev/null 2>&1 >/dev/null)
	rc=$?
	if [ "$rc" -eq 0 ]; then
		fail=$((fail + 1))
		echo "  FAIL [$name] 弾かれず成功した (exit=0)"
		return
	fi
	if printf '%s' "$err" | grep -q -- "$want"; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		echo "  FAIL [$name] エラーに '$want' が無い"
		echo "        実際: [$err]"
	fi
}

echo "--- 1. 名前として引く (単一文字) ---"
expect_out "md5 -s"        "MD5 (\"abc\") = $MD5_ABC" md5 -s abc
expect_out "md5 -q -s"     "$MD5_ABC"                 md5 -q -s abc
expect_out "md5 -q -r -s"  "$MD5_ABC"                 md5 -q -r -s abc

echo "--- 2. 連結 ---"
# 従来どおり通らなければならない. openssl は連結を認めないが, ここでは残している
expect_out "md5 -qr (2文字)"          "$MD5_ABC" md5 -qr -s abc
expect_out "md5 -rq (順序が逆)"       "$MD5_ABC" md5 -rq -s abc
expect_out "md5 -qrs (末尾が値)"      "$MD5_ABC" md5 -qrs abc
# 連結が実際に効いていることを, 結果が変わる組み合わせで確かめる.
# -d と -a を連結した復号は base64 でない入力なので必ず弾かれる.
# (連結が無視されるなら暗号化が走ってしまい, エラーにならない)
expect_err "des-ecb -da (連結が効く)" "bad decrypt" des-ecb -da -k 0011223344556677 -i "$TMP/in"

echo "--- 3. \"--name\" は名前として引くだけ ---"
expect_out "md5 --s"                  "MD5 (\"abc\") = $MD5_ABC" md5 --s abc
expect_out "pbkdf2 --c (値を取る)"    "dec72eebccd67343"         pbkdf2 -S s --c 2 -l 8
# 連結にはフォールバックしない. これが通るなら 3 の規則が壊れている
expect_err "md5 --qrs (連結にしない)" "illegal option -- qrs"    md5 --qrs abc

echo "--- 4. 値を取るオプションは連結の末尾のみ ---"
expect_err "md5 -sq (値が末尾でない)" "illegal option -- sq" md5 -sq abc

echo "--- 5. 弾くときは元の綴りを添える ---"
# 単一文字は従来と同じ文言 (des_mode.sh もこれを見ている)
expect_err "md5 -Z (単一文字)"     "illegal option -- Z"      md5 -Z
expect_err "des-ecb -Z (単一文字)" "illegal option -- Z"      des-ecb -Z -k 0011223344556677 -i "$TMP/in"
# 複数文字は綴りごと出す. 1文字ずつ見た結果だと 'illegal option -- u' になり伝わらない
expect_err "md5 -pubout (複数文字)" "illegal option -- pubout" md5 -pubout
expect_err "md5 --help (-- 付き)"   "illegal option -- help"   md5 --help

echo "--- 6. 値の欠落 ---"
expect_err "md5 -s (値が無い)"  "option requires an argument -- s" md5 -s
expect_err "md5 --s (値が無い)" "option requires an argument -- s" md5 --s

echo "--- 7. 表の kind ごとの経路 ---"
# OPTION_UINT32 / OPTION_UINT64 の範囲検査
expect_err "pbkdf2 -c 0 (下限)"    "too small"     pbkdf2 -S s -c 0
expect_err "pbkdf2 -c xyz (数値)"  "invalid value" pbkdf2 -S s -c xyz
expect_err "pbkdf2 -l 0 (下限)"    "too small"     pbkdf2 -S s -l 0
# OPTION_CUSTOM (名前から実体を引く)
expect_out "hmac -a md5"           "75972c9c6569f2f407752ddb02ac79de" hmac -a md5 -k "$TMP/key" "$TMP/in"
expect_err "hmac -a nosuch"        "unexpected hash algorithm name"   hmac -a nosuch -k "$TMP/key" "$TMP/in"
expect_err "pbkdf2 -a nosuch"      "unexpected PRF name"              pbkdf2 -S s -a nosuch
# OPTION_SET_FALSE (-e は -d を打ち消す)
expect_out "base64 -d -e (後が勝つ)" "YWJj" base64 -d -e -i "$TMP/in"
expect_out "base64 -e -d (後が勝つ)" "abc"  base64 -e -d -i "$TMP/b64"

echo
echo "=== options: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]
