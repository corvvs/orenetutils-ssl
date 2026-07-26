#!/bin/bash
# test/des_pcbc.sh — des-pcbc / des3-pcbc のテスト
#
# PCBC は OpenSSL に対応コマンドがない (des-pcbc は存在しない) ため,
# 暗号文をバイト比較して検証することができない. かわりに以下で担保する.
#
#   1) ECB から連鎖を手で再現して突き合わせる
#      C_i = E(P_i ^ P_{i-1} ^ C_{i-1})   (P_0 ^ C_0 = IV)
#      を ECB コマンドだけで組み立て, PCBC の出力と比較する.
#      ECB 側は OpenSSL と一致検証済みなので, PCBC の実装とは独立した検証になる.
#   2) 自己往復 (暗号化 -> 復号 で元に戻る)
#   3) IV が効いていること
#   4) 誤りが後続に伝播すること (PCBC の "Propagating" たるゆえん; CBC との違い)
#   5) パディングされること (ブロックモードなので長さは 8 の倍数に揃う)
#
# 使い方: bash test/des_pcbc.sh

set -u
SSL=./ft_ssl
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export FT_SSL_DEBUG=0

pass=0
fail=0
ok() { echo "OK   $1"; pass=$((pass + 1)); }
ng() { echo "FAIL $1"; fail=$((fail + 1)); }

# 16桁hex 同士の XOR
xor_hex() {
	local a=$1 b=$2 out="" i=0
	while [ $i -lt 16 ]; do
		out="$out$(printf '%x' $(( 0x${a:$i:1} ^ 0x${b:$i:1} )))"
		i=$((i + 1))
	done
	echo "$out"
}

# ECB で 1 ブロックだけ暗号化する (ft_ssl は必ずパディングするので先頭 8 オクテット)
# $1: コマンド, $2: 鍵, $3: 入力ブロック(16桁hex)
ecb_block() {
	printf '%s' "$3" | xxd -r -p | $SSL "$1" -k "$2" 2>/dev/null | head -c 8 | xxd -p | tr -d '\n'
}

# PCBC の暗号文を ECB だけで組み立てる
# $1: ecbコマンド, $2: 鍵, $3: IV(16桁hex), $4: 平文(hex, 8の倍数バイト)
build_pcbc() {
	local ecb=$1 key=$2 chain=$3 plain=$4
	local out="" i=0 p c
	while [ $i -lt ${#plain} ]; do
		p=${plain:$i:16}
		c=$(ecb_block "$ecb" "$key" "$(xor_hex "$p" "$chain")")
		out="$out$c"
		chain=$(xor_hex "$p" "$c")     # 次の連鎖値 = 平文 ^ 暗号文
		i=$((i + 16))
	done
	echo "$out"
}

# $1: ラベル, $2: pcbcコマンド, $3: ecbコマンド, $4: 鍵, $5: IV
check_against_ecb() {
	# パディングまで含めた平文を作る: 24バイト(3ブロック) + パディング1ブロック
	printf 'PCBC block one!!PCBC two' > "$TMP/p"
	local plain_padded mine expected
	# ft_ssl と同じ PKCS パディング (8バイト不足なので 0x08 が 8 個)
	plain_padded="$(xxd -p < "$TMP/p" | tr -d '\n')0808080808080808"
	mine=$($SSL "$2" -k "$4" -v "$5" < "$TMP/p" 2>/dev/null | xxd -p | tr -d '\n')
	expected=$(build_pcbc "$3" "$4" "$5" "$plain_padded")
	if [ "$mine" = "$expected" ]; then
		ok "$1: 暗号文が ECB から組み立てた連鎖と一致 (4ブロック)"
	else
		ng "$1: 不一致"
		echo "    mine    : $mine"
		echo "    expected: $expected"
	fi
}

# $1: ラベル, $2: コマンド, $3: 鍵, $4: IV
check_roundtrip() {
	local f
	for f in len0 len1 len7 len8 len9 len15 len17 len100 bin256; do
		$SSL "$2" -k "$3" -v "$4" < "$TMP/$f" 2>/dev/null > "$TMP/enc"
		$SSL "$2" -d -k "$3" -v "$4" < "$TMP/enc" 2>/dev/null > "$TMP/back"
		cmp -s "$TMP/$f" "$TMP/back" && ok "$1: 往復 $f" || ng "$1: 往復 $f"
		# ブロックモードなので 8 の倍数かつ必ず伸びる
		local n m
		n=$(wc -c < "$TMP/$f"); m=$(wc -c < "$TMP/enc")
		if [ $((m % 8)) -ne 0 ] || [ "$m" -le "$n" ]; then
			ng "$1: パディングされていない $f ($n -> $m)"
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

echo "### 1) ECB から連鎖を再現して検証 ###"
check_against_ecb "des-pcbc"  des-pcbc  des-ecb  $KEY  $IV
check_against_ecb "des3-pcbc" des3-pcbc des3-ecb $KEY3 $IV

echo
echo "### 2) 自己往復 ###"
check_roundtrip "des-pcbc"  des-pcbc  $KEY  $IV
check_roundtrip "des3-pcbc" des3-pcbc $KEY3 $IV

echo
echo "### 3) IV が効いていること ###"
a=$($SSL des-pcbc -k $KEY -v 0000000000000000 < "$TMP/len17" 2>/dev/null | xxd -p | tr -d '\n')
b=$($SSL des-pcbc -k $KEY -v 1111111111111111 < "$TMP/len17" 2>/dev/null | xxd -p | tr -d '\n')
[ "$a" != "$b" ] && ok "IV を変えると暗号文が変わる" || ng "IV が無視されている"

echo
echo "### 4) 誤りが後続に伝播すること (CBC との違い) ###"
# 3 ブロック以上の暗号文を作り, 先頭ブロックの 1 バイトを壊して復号する.
# CBC なら壊れるのは 2 ブロックまでだが, PCBC は以降すべてが壊れる.
printf 'AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD' > "$TMP/four"
for mode in des-cbc des-pcbc; do
	$SSL $mode -k $KEY -v $IV < "$TMP/four" 2>/dev/null > "$TMP/ct_$mode"
	# 先頭バイトを反転
	head=$(xxd -p < "$TMP/ct_$mode" | tr -d '\n')
	broken="$(printf '%02x' $(( 0x${head:0:2} ^ 0xff )))${head:2}"
	printf '%s' "$broken" | xxd -r -p > "$TMP/broken_$mode"
	$SSL $mode -d -k $KEY -v $IV < "$TMP/broken_$mode" 2>/dev/null > "$TMP/dec_$mode"
	# 最終ブロック (DDDDDDDD) が無傷かどうかを見る
	tail8=$(tail -c 8 "$TMP/dec_$mode" 2>/dev/null | xxd -p | tr -d '\n')
	echo "  $mode: 復号結果の末尾8バイト = ${tail8:-<復号失敗>}"
done
intact=$(printf 'DDDDDDDD' | xxd -p | tr -d '\n')
cbc_tail=$(tail -c 8 "$TMP/dec_des-cbc" 2>/dev/null | xxd -p | tr -d '\n')
pcbc_tail=$(tail -c 8 "$TMP/dec_des-pcbc" 2>/dev/null | xxd -p | tr -d '\n')
if [ "$cbc_tail" = "$intact" ] && [ "$pcbc_tail" != "$intact" ]; then
	ok "PCBC は末尾まで誤りが伝播する (CBC は伝播しない)"
else
	ng "誤り伝播の挙動が期待と異なる (cbc=$cbc_tail pcbc=$pcbc_tail expect_intact=$intact)"
fi

echo
echo "=== des-pcbc: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]
