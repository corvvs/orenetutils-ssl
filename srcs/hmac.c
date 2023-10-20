#include "ft_ssl.h"

static bool	is_key_reshaping_needed(
	const t_hash_algorithm* algorithm,
	const t_generic_message* key
) {
	return (key->byte_size != algorithm->block_byte_size);
}

// key に関する調整を行う:
// - 長すぎる場合は短く
// - 短すぎる場合はゼロパディング
static t_generic_message	reshape_key(
	const t_hash_algorithm* algorithm,
	const t_generic_message* key
) {
	yoyo_dprintf(STDOUT_FILENO, "original key: ");
	print_generic_message(key, STDOUT_FILENO);

	// 鍵がB(ハッシュのブロック長)より長い場合はハッシュする
	t_generic_message	truncated_key = new_generic_message(algorithm->block_byte_size);
	if (algorithm->block_byte_size < key->byte_size) {
		algorithm->func(&truncated_key, key);
	} else {
		copy_generic_message(&truncated_key, key);
		truncated_key.byte_size = key->byte_size;
	}

	yoyo_dprintf(STDOUT_FILENO, "truncated key: ");
	print_generic_message(&truncated_key, STDOUT_FILENO);

	// 鍵がBより短い場合は0x00でパディングする
	if (algorithm->block_byte_size > truncated_key.byte_size) {
		ft_memset(
			truncated_key.message + truncated_key.byte_size,
			0x00,
			algorithm->block_byte_size - truncated_key.byte_size
		);
		truncated_key.byte_size = algorithm->block_byte_size;
	}
	// truncated_key は reshape 不要のはず
	assert(!is_key_reshaping_needed(algorithm, &truncated_key));

	yoyo_dprintf(STDOUT_FILENO, "reshaped key: ");
	print_generic_message(&truncated_key, STDOUT_FILENO);

	return truncated_key;
}

t_generic_message	hmac(
	const t_hmac_hash_interface* hi,
	const t_generic_message* key,
	const t_generic_message* text
) {
	if (is_key_reshaping_needed(&hi->algorithm, key)) {
		// 鍵の reshape
		DEBUGOUT("func: %p", hi->algorithm.func);
		DEBUGOUT("block_byte_size: %zu", hi->algorithm.block_byte_size);
		DEBUGOUT("hash_byte_size: %zu", hi->algorithm.hash_byte_size);
		t_generic_message	reshaped_key = reshape_key(&hi->algorithm, key);
		t_generic_message	result = hmac(hi, &reshaped_key, text);
		destroy_generic_message(&reshaped_key);
		return result;
	}

	yoyo_dprintf(STDOUT_FILENO, "key: \t");
	print_generic_message(key, STDOUT_FILENO);

	t_generic_message	inner = dup_generic_message(key);
	yoyo_dprintf(STDOUT_FILENO, "inner: \t");
	print_generic_message(&inner, STDOUT_FILENO);

	// inner = key ^ ipad
	xor_assign_generic_message(&inner, &hi->ipad);
	yoyo_dprintf(STDOUT_FILENO, "inner ^ ipad: \t");
	print_generic_message(&inner, STDOUT_FILENO);

	// inner = inner + text
	join_assign_generic_message(&inner, text);
	yoyo_dprintf(STDOUT_FILENO, "inner + text: \t");
	print_generic_message(&inner, STDOUT_FILENO);

	// inner = H(inner)
	hi->algorithm.func(&inner, &inner);
	yoyo_dprintf(STDOUT_FILENO, "H(inner): \t");
	print_generic_message(&inner, STDOUT_FILENO);

	t_generic_message	outer = dup_generic_message(key);

	// outer = key ^ opad
	xor_assign_generic_message(&outer, &hi->opad);
	yoyo_dprintf(STDOUT_FILENO, "key ^ opad: \t");
	print_generic_message(&outer, STDOUT_FILENO);

	// outer = outer + inner
	join_assign_generic_message(&outer, &inner);
	yoyo_dprintf(STDOUT_FILENO, "outer + inner: \t");
	print_generic_message(&outer, STDOUT_FILENO);

	// H(outer)
	hi->algorithm.func(&outer, &outer);
	yoyo_dprintf(STDOUT_FILENO, "H(outer): \t");
	print_generic_message(&outer, STDOUT_FILENO);

	destroy_generic_message(&inner);
	return outer;
}