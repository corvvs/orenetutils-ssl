#!/bin/bash
# test/des_ctr.sh — des-ctr / des3-ctr のテスト
#
# CTR は OpenSSL に対応コマンドがない (des-ctr は存在しない) ため,
# 他のモードのように暗号文をバイト比較して検証することができない.
# そのかわり, 以下で正しさを担保する.
#
#   1) 鍵ストリームを ECB から独立に組み立てて突き合わせる
#      平文をゼロにすると C = 0 ^ keystream = keystream になるので,
#      CTR の出力そのものが鍵ストリームになる. これを
#      ECB(IV), ECB(IV+1), ECB(IV+2), ... の連結と比較する.
#      ECB 側は OpenSSL と一致検証済みなので, CTR の実装とは独立した検証になる.
#   2) 自己往復 (暗号化 -> 復号 で元に戻る)
#   3) 鍵ストリームがデータに依存しないこと
#   4) カウンタが実際に進んでいること
#   5) 桁上がり・上限での折り返し
#
# 使い方: bash test/des_ctr.sh

set -u
SSL=./ft_ssl
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export FT_SSL_DEBUG=0

pass=0
fail=0
ok() { echo "OK   $1"; pass=$((pass + 1)); }
ng() { echo "FAIL $1"; fail=$((fail + 1)); }

# ECB で 1 ブロックだけ暗号化する.
# ft_ssl は必ずパディングするので, 先頭 8 オクテットだけを取り出す.
# $1: コマンド(des-ecb|des3-ecb), $2: 鍵(hex), $3: 入力ブロック(16桁hex)
ecb_block() {
	printf '%s' "$3" | xxd -r -p | $SSL "$1" -k "$2" 2>/dev/null | head -c 8 | xxd -p | tr -d '\n'
}

# CTR の鍵ストリームを ECB から組み立てる.
# $1: ecbコマンド, $2: 鍵, $3: 初期カウンタ(16桁hex), $4: ブロック数
build_keystream() {
	local i=0
	while [ $i -lt $4 ]; do
		# 64bit カウンタとして +i (上限を超えたら折り返す)
		ecb_block "$1" "$2" "$(printf '%016x' $(( $3 + i )))"
		i=$((i + 1))
	done
}

# $1: ラベル, $2: ctrコマンド, $3: ecbコマンド, $4: 鍵, $5: IV(16桁hex), $6: ブロック数
check_keystream() {
	local blocks=$6
	head -c $((blocks * 8)) /dev/zero > "$TMP/zeros"
	local mine expected
	mine=$($SSL "$2" -k "$4" -v "$5" < "$TMP/zeros" 2>/dev/null | xxd -p | tr -d '\n')
	expected=$(build_keystream "$3" "$4" "0x$5" "$blocks")
	if [ "$mine" = "$expected" ]; then
		ok "$1: 鍵ストリームが ECB(IV+i) の連結と一致 (${blocks}ブロック)"
	else
		ng "$1: 鍵ストリーム不一致"
		echo "    mine    : $mine"
		echo "    expected: $expected"
	fi
}

# $1: ラベル, $2: ctrコマンド, $3: 鍵, $4: IV
check_roundtrip() {
	local f
	for f in len0 len1 len7 len8 len9 len15 len17 len100 bin256; do
		$SSL "$2" -k "$3" -v "$4" < "$TMP/$f" 2>/dev/null > "$TMP/enc"
		$SSL "$2" -d -k "$3" -v "$4" < "$TMP/enc" 2>/dev/null > "$TMP/back"
		if cmp -s "$TMP/$f" "$TMP/back"; then
			ok "$1: 往復 $f"
		else
			ng "$1: 往復 $f"
		fi
		# ストリームモードなので長さが保たれる
		if [ "$(wc -c < "$TMP/$f")" -ne "$(wc -c < "$TMP/enc")" ]; then
			ng "$1: 長さが変わった $f"
		fi
	done
}

# --- 入力データ ---
printf ''                    > "$TMP/len0"
printf 'A'                   > "$TMP/len1"
printf '1234567'             > "$TMP/len7"
printf '12345678'            > "$TMP/len8"
printf '123456789'           > "$TMP/len9"
printf '123456789012345'     > "$TMP/len15"
printf '12345678901234567'   > "$TMP/len17"
head -c 100 /dev/zero | tr '\0' 'x' > "$TMP/len100"
i=0
while [ $i -le 255 ]; do printf "\\$(printf '%03o' $i)"; i=$((i + 1)); done > "$TMP/bin256"

KEY=133457799bbcdff1
KEY3=0123456789abcdef23456789abcdef01456789abcdef0123
IV=0011223344556677

echo "### 1) 鍵ストリームを ECB から独立に検証 ###"
check_keystream "des-ctr"  des-ctr  des-ecb  $KEY  $IV 4
check_keystream "des3-ctr" des3-ctr des3-ecb $KEY3 $IV 4

echo
echo "### 2) 桁上がり・折り返し ###"
# 下位バイトが繰り上がる境界
check_keystream "des-ctr (carry)" des-ctr des-ecb $KEY 00000000000000fe 3
# 64bit の上限で 0 に戻る
check_keystream "des-ctr (wrap)"  des-ctr des-ecb $KEY fffffffffffffffe 3

echo
echo "### 3) 自己往復 ###"
check_roundtrip "des-ctr"  des-ctr  $KEY  $IV
check_roundtrip "des3-ctr" des3-ctr $KEY3 $IV

echo
echo "### 4) 暗号化と復号が同じ処理であること ###"
$SSL des-ctr -k $KEY -v $IV < "$TMP/len100" 2>/dev/null > "$TMP/c1"
$SSL des-ctr -k $KEY -v $IV < "$TMP/c1" 2>/dev/null > "$TMP/c2"
cmp -s "$TMP/len100" "$TMP/c2" && ok "暗号化を2回で元に戻る" || ng "暗号化を2回で元に戻らない"

echo
echo "### 5) 鍵ストリームがデータに依存しないこと ###"
# 同じ長さの別データを暗号化し, 暗号文の XOR が平文の XOR と一致するか
printf 'AAAAAAAAAAAAAAAA' > "$TMP/da"
printf 'BBBBBBBBBBBBBBBB' > "$TMP/db"
ca=$($SSL des-ctr -k $KEY -v $IV < "$TMP/da" 2>/dev/null | xxd -p | tr -d '\n')
cb=$($SSL des-ctr -k $KEY -v $IV < "$TMP/db" 2>/dev/null | xxd -p | tr -d '\n')
# 'A'^'B' = 0x03 が全バイトに現れるはず
diff_ok=1
i=0
while [ $i -lt 32 ]; do
	xa=$((0x${ca:$i:2})); xb=$((0x${cb:$i:2}))
	[ $((xa ^ xb)) -eq 3 ] || diff_ok=0
	i=$((i + 2))
done
[ $diff_ok -eq 1 ] && ok "暗号文の差分が平文の差分と一致 (鍵ストリーム共通)" || ng "鍵ストリームがデータに依存している"

echo
echo "### 6) カウンタが進んでいること (同一ブロックの繰り返しが隠れる) ###"
printf 'AAAAAAAAAAAAAAAAAAAAAAAA' > "$TMP/rep"
out=$($SSL des-ctr -k $KEY -v $IV < "$TMP/rep" 2>/dev/null | xxd -p | tr -d '\n')
b1=${out:0:16}; b2=${out:16:16}; b3=${out:32:16}
if [ "$b1" != "$b2" ] && [ "$b2" != "$b3" ]; then
	ok "同一平文ブロックが異なる暗号文になる"
else
	ng "同一平文ブロックが同じ暗号文になった (カウンタが進んでいない)"
fi

echo
echo "=== des-ctr: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]
