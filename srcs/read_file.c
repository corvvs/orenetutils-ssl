#include "ft_ssl.h"
#include "elastic_buffer.h"

// ifd から全データを読み取り, 1つの文字列に結合して返す
bool	read_file(t_master* master, int ifd, t_elastic_buffer* joined) {
	char	read_buffer[READ_BUFFER_SIZE];
	while (!joined->eof_reached) {
		// データを一定量読み取る
		errno = 0;
		ssize_t	read_size = read(ifd, read_buffer, sizeof(read_buffer));
		DEBUGOUT("read_size: %zd", read_size);
		if (read_size < 0) {
			return false;
		} else if (read_size == 0) {
			// データを読み切ったらループ脱出
			joined->eof_reached = true;
			break;
		}

		// 読み取ったデータを elastic_buffer に追加する
		errno = 0;
		if (!eb_push(joined, read_buffer, read_size, sizeof(read_buffer))) {
			PRINT_ERROR(master, "%s\n", strerror(errno));
			return false;
		}
	}
	return true;
}
