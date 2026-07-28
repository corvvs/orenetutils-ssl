# test/limited_run.sh — 制限時間つきでコマンドを実行する共通処理 (source して使う)
#
# timeout(1) は macOS の標準に無いため, 見張り役のサブシェルで代用する.
#
# 注意: 走らせる側も見張る側も, 明示的なサブシェルに入れて trap - EXIT すること.
# bash は EXIT トラップが設定されていると, バックグラウンドに回した単純コマンドでも
# 子シェルを残して終了時にトラップを走らせる. 呼び出し側が
# trap 'rm -rf "$TMP"' EXIT のような後始末を仕掛けていると, 1 件走らせるたびに
# 作業ディレクトリが消えることになる (bash 5 で実際に起きた. bash 3.2 では起きない).
# 起動できたかどうかを毎回確かめているのは, これを黙って見逃さないため.
#
# 使い方:
#   LIMITED_SEC=5
#   limited_run <標準入力> <標準出力の出力先> <標準エラーの出力先> <コマンド...>
#
# 戻り値:
#   0 = 有限時間で終了した (コマンド自身の終了コードは問わない)
#   1 = 制限時間を超えた
#   2 = シグナルで異常終了した
#   3 = そもそも起動できなかった (テスト側の不具合)

limited_run() {
	local stdin_path=$1
	local out_path=$2
	local err_path=$3
	shift 3

	rm -f "$out_path" "$err_path"
	( trap - EXIT; exec "$@" < "$stdin_path" > "$out_path" 2> "$err_path" ) &
	local target=$!

	# 見張り役は細かく刻んで眠る. こうしておくと, 用が済んで kill -9 されたときに
	# 取り残される sleep が 0.1 秒で終わり, 溜まらない.
	( trap - EXIT
		tick=0
		while [ "$tick" -lt "$((LIMITED_SEC * 10))" ]; do
			sleep 0.1
			tick=$((tick + 1))
		done
		kill -9 "$target" 2>/dev/null ) > /dev/null 2>&1 &
	local watchdog=$!

	wait "$target" 2>/dev/null
	local rc=$?

	# トラップを走らせずに確実に止めるため SIGKILL を使う
	kill -9 "$watchdog" 2>/dev/null
	wait "$watchdog" 2>/dev/null

	# 出力先が作れていないなら, コマンドを走らせられていない
	if [ ! -f "$out_path" ]; then
		return 3
	fi
	if [ "$rc" -eq 137 ]; then
		return 1
	fi
	if [ "$rc" -ge 128 ]; then
		return 2
	fi
	return 0
}
