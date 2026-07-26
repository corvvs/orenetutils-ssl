#!/bin/bash
# test/asan_docker.sh — Docker (Linux) 上で ASAN/UBSan 有効のままテストを回す
#
# macOS 側では AddressSanitizer のランタイムが動かない場合がある
# (malloc + printf だけの最小プログラムでも
#  "CHECK failed: sanitizer_malloc_mac.inc ... asan_init_is_running" で落ちる).
# その場合でも Linux コンテナなら Makefile 既定の CFLAGS のまま検証できる.
#
# リポジトリは読み取り専用でマウントし, コンテナ内にコピーしてビルドする.
# (ホストの objs/ や ft_ssl を Linux バイナリで上書きしないため)
#
# 使い方: bash test/asan_docker.sh ["<コマンド名> [IV]" ...]
#   bash test/asan_docker.sh                                    # 既定の全モード
#   bash test/asan_docker.sh "des-cbc 0011223344556677"         # 指定モードのみ
# 各引数はそのまま test/des_mode.sh の引数になる.

set -u
IMAGE=ft_ssl_dev

if [ $# -eq 0 ]; then
	set -- "--ctr" "des-ecb des-ecb" "des-cbc des-cbc 0011223344556677"
fi

docker build -t "$IMAGE" ./docker || exit 1

docker run --rm -v "$PWD":/src:ro "$IMAGE" bash -c '
	set -u
	cp -r /src /build && cd /build
	# ホストで作られた macOS のオブジェクトが混ざらないよう作り直す
	make fclean >/dev/null 2>&1
	if ! make >/dev/null 2>&1; then
		echo "build failed"
		make
		exit 1
	fi

	# サニタイザの報告はファイルに出す.
	# テストスクリプトが stderr を /dev/null に捨てても取りこぼさないため.
	rm -f /build/sanlog.*
	export ASAN_OPTIONS=detect_leaks=1:detect_stack_use_after_return=1:log_path=/build/sanlog
	export UBSAN_OPTIONS=print_stacktrace=1:log_path=/build/sanlog

	status=0
	for spec in "$@"; do
		if [ "$spec" = "--ctr" ]; then
			# CTR は OpenSSL に対応コマンドがなく専用スクリプトで検証する
			echo "### des_ctr.sh ###"
			bash test/des_ctr.sh || status=1
			continue
		fi
		echo "### des_mode.sh $spec ###"
		# $spec は "des-cbc <IV>" のように複数語なので, あえて分割させる
		bash test/des_mode.sh $spec || status=1
	done

	echo
	echo "=== sanitizer reports ==="
	if ls /build/sanlog.* >/dev/null 2>&1; then
		cat /build/sanlog.*
		echo "!! サニタイザが問題を報告しました"
		status=1
	else
		echo "(なし)"
	fi
	exit $status
' _ "$@"
