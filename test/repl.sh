#!/bin/bash
# test/repl.sh — 対話モード (REPL) の頑健性テスト
#
# REPL は「1行読む -> 実行する -> 読んだ分をバッファから消す」を繰り返す.
# 消す量を取り違えると入力が減らないまま次の周回に入り, 無限ループになる.
# 実際, 末尾が改行で終わらない入力 (例: printf 'help\nhelp') で
# プロンプトを出し続けて終わらなくなる不具合があった.
#
# ここでは次の3点を確認する.
#   a) どんな入力でも有限時間で終了する
#   b) シグナルで死なない
#   c) 正常な入力では従来どおりの結果が出る
#
# 前提: プロジェクトルートで ./ft_ssl をビルド済みであること.
# 使い方: bash test/repl.sh

set -u
SSL=./ft_ssl
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# デバッグ出力抑制フラグ
export FT_SSL_DEBUG=0

. "$(dirname "$0")/limited_run.sh"

pass=0
fail=0

# 1件あたりの制限時間 (秒)
LIMITED_SEC=5

# 入力を与えて「有限時間で終わること」だけを確かめる
check_terminates() { # check_terminates <名前> <入力ファイル>
	limited_run "$2" "$TMP/out" "$TMP/err" "$SSL"
	case $? in
		0) pass=$((pass + 1)) ;;
		1) fail=$((fail + 1)); echo "  FAIL [$1] ${LIMITED_SEC}秒で終わらない (無限ループ)" ;;
		2) fail=$((fail + 1)); echo "  FAIL [$1] シグナルで異常終了" ;;
		3) fail=$((fail + 1)); echo "  FAIL [$1] 起動できなかった (テスト側の不具合)" ;;
	esac
}

# 入力を与えて, 出力に期待する文字列が現れることを確かめる
check_output() { # check_output <名前> <入力文字列> <期待する部分文字列>
	printf '%s' "$2" > "$TMP/in"
	limited_run "$TMP/in" "$TMP/out" "$TMP/err" "$SSL"
	local rc=$?
	if [ "$rc" -ne 0 ]; then
		fail=$((fail + 1))
		echo "  FAIL [$1] 終了しない, 異常終了した, または起動できなかった (rc=$rc)"
		return
	fi
	if grep -q -- "$3" "$TMP/out" "$TMP/err" 2>/dev/null; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		echo "  FAIL [$1] 出力に '$3' が無い"
		echo "        実際の stdout: [$(head -c 200 "$TMP/out" | tr -d '\0' | tr '\n' '|')]"
		echo "        実際の stderr: [$(head -c 200 "$TMP/err" | tr -d '\0' | tr '\n' '|')]"
	fi
}

echo "--- 末尾が改行で終わらない入力 (無限ループの再現ケース) ---"
printf '\nx'              > "$TMP/t"; check_terminates "改行の直後に1文字"     "$TMP/t"
printf 'help\nhelp'       > "$TMP/t"; check_terminates "2行目に改行が無い"     "$TMP/t"
printf '\n '              > "$TMP/t"; check_terminates "改行の後に空白のみ"    "$TMP/t"
printf '\n\t'             > "$TMP/t"; check_terminates "改行の後にタブのみ"    "$TMP/t"
printf '\n\x00'           > "$TMP/t"; check_terminates "改行の後に NUL のみ"   "$TMP/t"
printf 'md5 -s a\nnosuch' > "$TMP/t"; check_terminates "有効な行 + 未完の行"   "$TMP/t"

echo "--- 読み取り単位 (READ_SIZE = 4096) の境界 ---"
for n in 4095 4096 4097; do
	{ head -c "$n" /dev/zero | tr '\0' 'z'; printf '\n'; head -c 10 /dev/zero | tr '\0' 'y'; } > "$TMP/t"
	check_terminates "改行位置=$n の後に改行無しデータ" "$TMP/t"
	{ head -c "$n" /dev/zero | tr '\0' 'z'; printf '\n'; } > "$TMP/t"
	check_terminates "改行位置=$n でちょうど終端"       "$TMP/t"
done

echo "--- 制御文字・バイナリ・空 ---"
: > "$TMP/t";                                    check_terminates "空入力"           "$TMP/t"
printf '\n'                          > "$TMP/t"; check_terminates "改行のみ"         "$TMP/t"
printf '\n\n\n'                      > "$TMP/t"; check_terminates "改行が3つ"        "$TMP/t"
head -c 5000 /dev/zero               > "$TMP/t"; check_terminates "NUL が5000個"     "$TMP/t"
head -c 200000 /dev/urandom          > "$TMP/t"; check_terminates "ランダム 200KB"   "$TMP/t"
ruby -e 'STDOUT.binmode; STDOUT.write((0..255).map(&:chr).join)' > "$TMP/t"
check_terminates "全バイト値 0x00-0xff" "$TMP/t"

echo "--- 無作為な入力 (種を固定するので毎回同じものを試す) ---"
ruby -e '
	srand(1234)
	dir = ARGV[0]
	# 改行・空白・NUL とコマンド名の断片を混ぜる
	alphabet = "\n md5 help - \x00\t\rabc0123".bytes
	100.times do |i|
		body = (0...rand(300)).map { alphabet.sample.chr }.join
		File.binwrite(format("%s/fz%03d", dir, i), body)
	end
' "$TMP"
for f in "$TMP"/fz*; do
	check_terminates "無作為 $(basename "$f")" "$f"
done

echo "--- 正常な入力での結果 ---"
check_output "md5 が動く"    'md5 -s abc
'    '900150983cd24fb0d6963f7d28e17f72'
check_output "sha256 が動く" 'sha256 -s abc
'    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
check_output "未知のコマンドは報告される" 'nosuchcommand
'    'invalid command'
# 末尾に改行が無くても, その行のコマンドは実行されなければならない
check_output "末尾に改行が無くても実行される" 'md5 -s abc' '900150983cd24fb0d6963f7d28e17f72'

echo
echo "=== repl: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]
