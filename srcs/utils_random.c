#include "ft_ssl.h"

// [乱数の取得]
// /dev/urandom から読む. 許可関数 (open / read / close) だけで済み,
// arc4random や getentropy のような追加シンボルを持ち込まずに
// 暗号用途に足る乱数が得られる.
//
// fd は一度開いたら閉じずに使い回す.
// RSA の鍵生成は素数が見つかるまで候補を作り直すので, 1 回の genrsa でも
// 数百回の要求が来る. 要求ごとに開き直すのは無駄なだけでなく,
// 「最初は開けたのに途中から開けない」という扱いにくい失敗を増やす.
// プロセスが動いている間ずっと必要なものなので, 意図的に開いたままにする.
static int	g_urandom_fd = -1;

// out に size オクテットの乱数を書く. 全部書けたときだけ true.
// (失敗の報告は呼び出し側が行う; ここは用途を知らないのでメッセージを持てない)
bool	random_bytes(void* out, size_t size) {
	if (g_urandom_fd < 0) {
		g_urandom_fd = open("/dev/urandom", O_RDONLY);
		if (g_urandom_fd < 0) {
			return false;
		}
	}

	uint8_t*	head = out;
	while (size > 0) {
		const ssize_t	n = read(g_urandom_fd, head, size);
		// urandom で 0 が返ることはないが, 進まないまま回り続けないよう失敗にする
		if (n <= 0) {
			return false;
		}
		head += n;
		size -= (size_t)n;
	}
	return true;
}
