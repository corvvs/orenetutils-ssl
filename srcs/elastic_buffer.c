#include "elastic_buffer.h"

static bool	extend_buffer(
	t_elastic_buffer* elastic_buffer,
	size_t cap
) {
	// 拡張不要なら early return
	if (elastic_buffer->capacity >= cap) {
		return (true);
	}

	// 拡張後のバッファをアロケートする
	elastic_buffer->capacity = cap;
	char*	extended_buffer = malloc(elastic_buffer->capacity);
	if (extended_buffer == NULL) {
		DEBUGERR("failed to extend: %zu", elastic_buffer->capacity);
		return (false);
	}

	// データを移動してから古い方を破壊する
	ft_memcpy(extended_buffer, elastic_buffer->buffer, elastic_buffer->used);
	free(elastic_buffer->buffer);
	elastic_buffer->buffer = extended_buffer;
	return (true);
}

// 要求サイズ増分に対して必要なら elastic_buffer を拡張する.
// 拡張に失敗した場合は false, そうでなければ true を返す.
static bool	extend_by_demand(
	t_elastic_buffer* elastic_buffer,
	size_t required_more,
	size_t minimum_cap
) {
	// 拡張不要なら early return
	const size_t	least_capacity = elastic_buffer->used + required_more;
	if (elastic_buffer->capacity >= least_capacity) {
		return (true);
	}

	return extend_buffer(elastic_buffer, elastic_buffer->capacity > 0
		? elastic_buffer->capacity * 2
		: minimum_cap);
}

bool	eb_reserve(
	t_elastic_buffer* elastic_buffer,
	size_t cap
) {
	return extend_buffer(elastic_buffer, cap);
}

// elastic_buffer にデータを保存する
// (必要に応じて elastic_buffer を拡張する)
bool	eb_push(
	t_elastic_buffer* elastic_buffer,
	const void* data,
	size_t data_size,
	size_t minimum_cap
) {
	// data が収まるようにしておく
	if (!extend_by_demand(elastic_buffer, data_size, minimum_cap)) {
		return (false);
	}

	// data をバッファ末尾に追記する
	ft_memcpy(elastic_buffer->buffer + elastic_buffer->used, data, data_size);
	elastic_buffer->used += data_size;
	return true;
}

void	eb_truncate_front(t_elastic_buffer* elastic_buffer, size_t data_size) {
	if (elastic_buffer->used > data_size) {
		ft_memmove(elastic_buffer->buffer, elastic_buffer->buffer + data_size, elastic_buffer->used - data_size);
	}
	elastic_buffer->used -= data_size;
}

t_elastic_buffer	eb_release(t_elastic_buffer* from) {
	t_elastic_buffer	out = *from;
	*from = (t_elastic_buffer) {
		.eof_reached = from->eof_reached,
	};
	return out;
}
