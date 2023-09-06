#include "ft_ssl.h"
#include "elastic_buffer.h"

#define READ_BUFFER_SIZE (128 << 10)

// ifd から全データを読み取り, 1つの文字列に結合して返す
bool	read_file(const t_master* master, int ifd, t_elastic_buffer* buffer_ptr) {
	t_elastic_buffer	joined = {
		.capacity = READ_BUFFER_SIZE,
		.buffer = malloc(READ_BUFFER_SIZE),
	};
	if (joined.buffer == NULL) {
		print_error_by_errno(master);
		return false;
	}
	char	read_buffer[READ_BUFFER_SIZE];

	while (true) {
		// データを一定量読み取る
		ssize_t	read_size = read(ifd, read_buffer, sizeof(read_buffer));
		if (read_size < 0) {
			DEBUGERR("read error: %zd", read_size);
			free(joined.buffer);
			return (NULL);
		} else if (read_size == 0) {
			// データを読み切ったらループ脱出
			break ;
		}

		// 読み取ったデータを elastic_buffer に追加する
		if (!push_to_elastic_buffer(&joined, read_buffer, read_size, sizeof(read_buffer))) {
			free(joined.buffer);
			return (NULL);
		}
	}
	*buffer_ptr = joined;
	return true;
}
