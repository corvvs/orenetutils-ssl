#!/bin/bash
# test/cli_robustness.sh — 壊れた入力を与えてもクラッシュ・ハングしないことの確認
#
# 正しい入力に対する答え合わせは des_mode.sh / *_simple.sh / hmac.rb が行う.
# こちらは「異常な入力で落ちないこと」だけを見る. 見るのは次の2つだけで,
# 終了コードやメッセージの中身は問わない.
#   - シグナルで死んでいないか
#   - 有限時間で終わっているか
# ASAN/UBSan ビルドで走らせた場合は, 出力に混ざる検出報告も失敗として扱う.
#
# 前提: プロジェクトルートで ./ft_ssl をビルド済みであること.
# 使い方: bash test/cli_robustness.sh

set -u
SSL=./ft_ssl
TMP=$(mktemp -d)
trap 'chmod -R u+rwX "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

# デバッグ出力抑制フラグ
export FT_SSL_DEBUG=0

. "$(dirname "$0")/limited_run.sh"

pass=0
fail=0
LIMITED_SEC=20

KEY=0011223344556677
KEY3=00112233445566778899aabbccddeeff0011223344556677

# ft_ssl を制限時間つきで走らせ, 落ちていないことを確かめる.
# 標準入力は /dev/null に固定する (パスワード等を待って止まらないようにするため).
check() { # check <名前> <ft_ssl に渡す引数...>
	local name=$1
	shift
	limited_run /dev/null "$TMP/out" "$TMP/err" "$SSL" "$@"
	case $? in
		1) fail=$((fail + 1)); echo "  FAIL [$name] ${LIMITED_SEC}秒で終わらない"; return ;;
		2) fail=$((fail + 1)); echo "  FAIL [$name] シグナルで異常終了"; return ;;
		3) fail=$((fail + 1)); echo "  FAIL [$name] 起動できなかった (テスト側の不具合)"; return ;;
	esac
	# ASAN/UBSan ビルドのときだけ意味を持つ
	if grep -qE 'AddressSanitizer|LeakSanitizer|runtime error:' "$TMP/err" 2>/dev/null; then
		fail=$((fail + 1))
		echo "  FAIL [$name] $(grep -E 'AddressSanitizer|LeakSanitizer|runtime error:' "$TMP/err" | head -1)"
		return
	fi
	pass=$((pass + 1))
}

DIGESTS="md5 sha224 sha256 sha384 sha512 sha512-224 sha512-256"
DES_MODES="des des-ecb des-cbc des-ofb des-cfb des-ctr des-pcbc"
DES3_MODES="des3 des3-ecb des3-cbc des3-ofb des3-cfb des3-ctr des3-pcbc"
ALL="help test hmac pbkdf2 base64 $DIGESTS $DES_MODES $DES3_MODES"

LONG=$(head -c 20000 /dev/zero | tr '\0' 'X')

# macOS の head は -c 0 を受け付けないので, 0 バイトだけは空ファイルとして作る
make_random() { # make_random <バイト数> <出力先>
	if [ "$1" -eq 0 ]; then
		: > "$2"
	else
		head -c "$1" /dev/urandom > "$2"
	fi
}

echo "--- コマンド名とオプション ---"
for c in $ALL; do
	check "引数なし: $c" "$c"
done
check "未知のコマンド"      nosuchcommand
check "空のコマンド名"      ""
check "ハイフンのみ"        -
check "ハイフン2つ"         --
check "とても長い名前"      "$LONG"
check "パス風のコマンド名"  ../../etc/passwd
check "非 ASCII のコマンド名" 日本語
for c in md5 base64 des-ecb hmac pbkdf2; do
	check "未知のオプション: $c"      "$c" -Z
	check "ハイフンのみ: $c"          "$c" -
	check "ハイフンが5つ: $c"         "$c" -----
	check "とても長いオプション: $c"  "$c" "-$LONG"
done
# 値を要求するオプションが引数列の末尾にある
for o in k v s p i o; do
	check "値の無い -$o" des-ecb "-$o"
done
check "値を取るオプションに後続文字" des-ecb -ke "$KEY"
check "オプションの重複"             des-ecb -k 00 -k 11
check "-d と -e の併用"              des-ecb -d -e -k "$KEY"

echo "--- 16進の解釈 (-k / -v / -s) ---"
head -c 8 /dev/urandom > "$TMP/in8"
for o in k v s; do
	check "空文字: -$o"        des-cbc "-$o" ""             -i "$TMP/in8"
	check "奇数桁: -$o"        des-cbc "-$o" abc            -i "$TMP/in8"
	check "非16進: -$o"        des-cbc "-$o" zzzzzzzz       -i "$TMP/in8"
	check "途中から非16進: -$o" des-cbc "-$o" 00zz11        -i "$TMP/in8"
	check "0x 前置: -$o"       des-cbc "-$o" 0x00112233     -i "$TMP/in8"
	check "負号: -$o"          des-cbc "-$o" -1             -i "$TMP/in8"
	check "空白入り: -$o"      des-cbc "-$o" "00 11 22"     -i "$TMP/in8"
	check "非 ASCII: -$o"      des-cbc "-$o" あいう          -i "$TMP/in8"
	check "とても長い: -$o"    des-cbc "-$o" "$LONG"        -i "$TMP/in8"
done
check "3DES に短すぎる鍵" des3-cbc -k 00 -i "$TMP/in8"

echo "--- ファイルの指定 ---"
mkdir -p "$TMP/adir"
printf 'x' > "$TMP/noread"; chmod 000 "$TMP/noread"
ln -s "$TMP/loop" "$TMP/loop" 2>/dev/null
: > "$TMP/empty"
for c in md5 base64 des-ecb; do
	check "存在しない入力: $c"         "$c" -i "$TMP/nonexistent"
	check "入力がディレクトリ: $c"     "$c" -i "$TMP/adir"
	check "読めない入力: $c"           "$c" -i "$TMP/noread"
	check "シンボリックリンクの輪: $c" "$c" -i "$TMP/loop"
	check "/dev/null: $c"              "$c" -i /dev/null
	check "空ファイル: $c"             "$c" -i "$TMP/empty"
done
check "出力先がディレクトリ"   md5 -i "$TMP/in8" -o "$TMP/adir"
check "出力先の親が無い"       md5 -i "$TMP/in8" -o "$TMP/nodir/x"
check "入力と出力が同じファイル" des-ecb -k "$KEY" -i "$TMP/in8" -o "$TMP/in8"

echo "--- 入力データの長さ ---"
for n in 0 1 7 8 9 15 16 17 63 64 65; do
	make_random "$n" "$TMP/n"
	for c in md5 sha512 base64 des-ecb des-cbc des-ofb des-ctr des3-cbc; do
		check "長さ$n: $c"       "$c" -k "$KEY3" -i "$TMP/n"
		check "長さ$n 復号: $c"  "$c" -d -k "$KEY3" -i "$TMP/n"
	done
done
ruby -e 'STDOUT.binmode; STDOUT.write(((0..255).map(&:chr).join) * 16)' > "$TMP/allbytes"
check "全バイト値: md5"     md5     -i "$TMP/allbytes"
check "全バイト値: base64"  base64  -i "$TMP/allbytes"
check "全バイト値: des-cbc" des-cbc -k "$KEY" -i "$TMP/allbytes"

echo "--- パディングの検査 (復号後の平文を狙って作る) ---"
# パディングありで 8 バイトを暗号化すると E(P) || E(パディングブロック) になるので,
# 先頭 8 バイトが E(P) そのもの. これを暗号文として復号させれば,
# パディング検査が見る 1 ブロックを完全に指定できる.
check_padding() { # check_padding <名前> <平文8バイトの printf 表記>
	printf "$2" > "$TMP/pt"
	if [ "$(wc -c < "$TMP/pt")" -ne 8 ]; then
		fail=$((fail + 1)); echo "  FAIL [$1] 平文が8バイトになっていない"; return
	fi
	"$SSL" des-ecb -k "$KEY" -i "$TMP/pt" 2>/dev/null | head -c 8 > "$TMP/ct"
	check "$1" des-ecb -d -k "$KEY" -i "$TMP/ct"
}
check_padding "パディング長 0x00 (不正)"        '\x41\x41\x41\x41\x41\x41\x41\x00'
check_padding "パディング長 0x09 (大きすぎ)"    '\x41\x41\x41\x41\x41\x41\x41\x09'
check_padding "パディング長 0xff (大きすぎ)"    '\x41\x41\x41\x41\x41\x41\x41\xff'
check_padding "パディング長 0x08 (全体が詰め物)" '\x08\x08\x08\x08\x08\x08\x08\x08'
check_padding "パディング長 0x07 (正当)"        '\x07\x07\x07\x07\x07\x07\x07\x07'
check_padding "パディングの中身が不一致"        '\x01\x02\x03\x04\x05\x06\x07\x08'

echo "--- 壊れた暗号文 ---"
for n in 1 2 3 7 8 9 15 16 17 23; do
	head -c "$n" /dev/urandom > "$TMP/ct"
	for m in des-ecb des-cbc des-pcbc des-ofb des-cfb des-ctr des3-cbc; do
		check "$n バイトを復号: $m" "$m" -d -k "$KEY3" -i "$TMP/ct"
	done
done
printf 'Salted__'                       > "$TMP/h";  check "ヘッダ8バイトのみ"       des-cbc -d -p pw -i "$TMP/h"
printf 'Salted__\x01\x02\x03\x04'       > "$TMP/h";  check "ヘッダ途中まで"          des-cbc -d -p pw -i "$TMP/h"
printf 'Salted__12345678'               > "$TMP/h";  check "ヘッダのみで本体が無い"  des-cbc -d -p pw -i "$TMP/h"
printf 'Salted__12345678\x01'           > "$TMP/h";  check "本体が1バイト"           des-cbc -d -p pw -i "$TMP/h"
printf 'Salted_X12345678ABCDEFGH'       > "$TMP/h";  check "マジックが壊れている"    des-cbc -d -p pw -i "$TMP/h"
printf 'SALTED__12345678ABCDEFGH'       > "$TMP/h";  check "マジックが大文字"        des-cbc -d -p pw -i "$TMP/h"
printf 'Salted__12345678ABCDEFGH'       > "$TMP/h";  check "ヘッダあり + -s 併用"    des-cbc -d -p pw -s "$KEY" -i "$TMP/h"
printf 'Salted__12345678ABCDEFGH'       > "$TMP/h";  check "ストリームモードで復号"  des-ofb -d -p pw -i "$TMP/h"

echo "--- base64 経由 (-a) ---"
: > "$TMP/b64.0"
printf '='            > "$TMP/b64.1"
printf '===='         > "$TMP/b64.2"
printf 'A'            > "$TMP/b64.3"
printf 'AB'           > "$TMP/b64.4"
printf 'ABC'          > "$TMP/b64.5"
printf '@@@@'         > "$TMP/b64.6"
printf 'AAAA=AAA'     > "$TMP/b64.7"
printf 'AAAA\n\n\nAAAA' > "$TMP/b64.8"
printf 'AAAA AAAA'    > "$TMP/b64.9"
head -c 4096 /dev/urandom > "$TMP/b64.10"
head -c 100000 /dev/zero | tr '\0' 'A' > "$TMP/b64.11"
for f in "$TMP"/b64.*; do
	n=$(basename "$f")
	check "base64 -d: $n"      base64   -d      -i "$f"
	check "des-cbc -a -d: $n"  des-cbc  -d -a -k "$KEY"  -i "$f"
	check "des3-cbc -a -d: $n" des3-cbc -d -a -k "$KEY3" -i "$f"
done

echo "--- パスワード ---"
check "空のパスワード" des-cbc -p "" -i "$TMP/in8"
for n in 1 1023 1024 5000; do
	pw=$(head -c "$n" /dev/zero | tr '\0' 'a')
	check "パスワード $n 文字" des-cbc -p "$pw" -i "$TMP/in8"
done
check "非 ASCII のパスワード" des-cbc -p "パスワード" -i "$TMP/in8"
# 標準入力からのパスワード読み取り (check は標準入力を /dev/null にするので即 EOF)
check "パスワード入力が即 EOF" des-cbc -i "$TMP/in8"

# PBKDF2 は同じ鍵で PRF を1万回まわす. 鍵の整形を反復の内側でやっていると
# 所要時間がパスワード長に比例してしまう (30万文字で約7秒かかっていた).
# 整形を反復の外に出せば長さによらず一定 (約0.02秒) になる.
saved_limit=$LIMITED_SEC
LIMITED_SEC=3
long_pw=$(head -c 300000 /dev/zero | tr '\0' 'a')
check "30万文字のパスワードが ${LIMITED_SEC}秒以内に終わる" des-cbc -p "$long_pw" -i "$TMP/in8" -o /dev/null
LIMITED_SEC=$saved_limit

echo
echo "=== cli_robustness: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]
