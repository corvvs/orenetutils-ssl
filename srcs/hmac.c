#include "ft_ssl.h"
#include "generic_message.h"

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
	// yoyo_dprintf(STDOUT_FILENO, "original key: ");
	// print_generic_message_hex(key, STDOUT_FILENO);

	// 鍵がB(ハッシュのブロック長)より長い場合はハッシュする
	t_generic_message	truncated_key = new_generic_message(algorithm->block_byte_size);
	if (algorithm->block_byte_size < key->byte_size) {
		algorithm->func(&truncated_key, key);
	} else {
		copy_generic_message(&truncated_key, key);
		truncated_key.byte_size = key->byte_size;
	}

	// yoyo_dprintf(STDOUT_FILENO, "truncated key: ");
	// print_generic_message_hex(&truncated_key, STDOUT_FILENO);

	// 鍵がBより短い場合は0x00でパディングする
	if (algorithm->block_byte_size > truncated_key.byte_size) {
		ft_memset(
			truncated_key.message + truncated_key.byte_size,
			0x00,
			algorithm->block_byte_size - truncated_key.byte_size
		);
		// DEBUGWARN("padding key: %zu -> %zu", truncated_key.byte_size, algorithm->block_byte_size);
		truncated_key.byte_size = algorithm->block_byte_size;
	}
	// truncated_key は reshape 不要のはず
	assert(!is_key_reshaping_needed(algorithm, &truncated_key));

	// yoyo_dprintf(STDOUT_FILENO, "reshaped key: ");
	// print_generic_message_hex(&truncated_key, STDOUT_FILENO);

	return truncated_key;
}

t_generic_message	hmac(
	const t_hmac_hash_interface* hi,
	const t_generic_message* key,
	const t_generic_message* text
) {
	if (is_key_reshaping_needed(&hi->algorithm, key)) {
		// 鍵の reshape
		// DEBUGOUT("func: %p", hi->algorithm.func);
		// DEBUGOUT("block_byte_size: %zu", hi->algorithm.block_byte_size);
		// DEBUGOUT("hash_byte_size: %zu", hi->algorithm.hash_byte_size);
		t_generic_message	reshaped_key = reshape_key(&hi->algorithm, key);
		t_generic_message	result = hmac(hi, &reshaped_key, text);
		destroy_generic_message(&reshaped_key);
		return result;
	}

	// yoyo_dprintf(STDOUT_FILENO, "key: \t");
	// print_generic_message_hex(key, STDOUT_FILENO);

	t_generic_message	inner = dup_generic_message(key);
	// yoyo_dprintf(STDOUT_FILENO, "inner: \t");
	// print_generic_message_hex(&inner, STDOUT_FILENO);

	// inner = key ^ ipad
	xor_assign_generic_message(&inner, &hi->ipad);
	// yoyo_dprintf(STDOUT_FILENO, "inner ^ ipad: \t");
	// print_generic_message_hex(&inner, STDOUT_FILENO);

	// inner = inner + text
	join_assign_generic_message(&inner, text);
	// yoyo_dprintf(STDOUT_FILENO, "inner + text: \t");
	// print_generic_message_hex(&inner, STDOUT_FILENO);

	// inner = H(inner)
	hi->algorithm.func(&inner, &inner);
	// yoyo_dprintf(STDOUT_FILENO, "H(inner): \t");
	// print_generic_message_hex(&inner, STDOUT_FILENO);

	t_generic_message	outer = dup_generic_message(key);

	// outer = key ^ opad
	xor_assign_generic_message(&outer, &hi->opad);
	// yoyo_dprintf(STDOUT_FILENO, "key ^ opad: \t");
	// print_generic_message_hex(&outer, STDOUT_FILENO);

	// outer = outer + inner
	join_assign_generic_message(&outer, &inner);
	// yoyo_dprintf(STDOUT_FILENO, "outer + inner: \t");
	// print_generic_message_hex(&outer, STDOUT_FILENO);

	// H(outer)
	hi->algorithm.func(&outer, &outer);
	// yoyo_dprintf(STDOUT_FILENO, "H(outer): \t");
	// print_generic_message_hex(&outer, STDOUT_FILENO);

	destroy_generic_message(&inner);

	// yoyo_dprintf(STDOUT_FILENO, "hash algorithm: \t%s\n", hi->name);
	// yoyo_dprintf(STDOUT_FILENO, "key: \t");
	// print_generic_message_ascii(key, STDOUT_FILENO);
	// yoyo_dprintf(STDOUT_FILENO, "text: \t");
	// print_generic_message_ascii(text, STDOUT_FILENO);
	// yoyo_dprintf(STDOUT_FILENO, "HMAC: \t");
	// print_generic_message_hex(&outer, STDOUT_FILENO);

	return outer;
}

int	run_hmac(t_master* master, char **argv) {
	t_master_hmac	m = {
		.master = *master,
	};
	t_preference*	pref = &m.pref;
	int parsed_count = parse_options_hmac(master, argv, pref);
	if (parsed_count < 0) {
		return 1;
	}
	argv += parsed_count;

	if (pref->hi == NULL) {
		PRINT_ERROR(master, "algorithm is unspecified\n", "");
		return 1;
	}
	DEBUGINFO("algorithm: %s", pref->hi->name);

	if (pref->path_key == NULL) {
		PRINT_ERROR(master, "path for key is required.\n", "");
		return 1;
	}
	t_generic_message	key = new_generic_message_path(&m.master, pref->path_key);
	if (key.message == NULL) {
		return 1;
	}
	DEBUGINFO("key size: %zu", key.byte_size);

	t_generic_message	data;
	if (*argv == NULL) {
		data = new_generic_message_stdin(&m.master);
	} else {
		DEBUGOUT("read data from path: %s", *argv);
		data = new_generic_message_path(&m.master, *argv);
	}
	if (data.message == NULL) {
		destroy_generic_message(&key);
		return 1;
	}
	DEBUGINFO("data size: %zu", data.byte_size);

	t_generic_message	mac =  hmac(pref->hi, &key, &data);
	if (mac.message != NULL) {
		print_generic_message_hex(&mac, STDOUT_FILENO);
		yoyo_dprintf(STDOUT_FILENO, "\n");
	}

	destroy_generic_message(&key);
	destroy_generic_message(&data);
	destroy_generic_message(&mac);
	return 0;
}
