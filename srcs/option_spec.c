#include "ft_ssl.h"

// [オプション定義表による解析]
// 規則は includes/option_parser.h の冒頭に書いてある.

static const t_option_spec*	find_spec(const t_option_spec* specs, const char* name) {
	for (size_t i = 0; specs[i].name != NULL; ++i) {
		if (ft_strcmp(specs[i].name, name) == 0) {
			return &specs[i];
		}
	}
	return NULL;
}

// その綴りのオプションが値を取るかどうか
static bool	takes_value(const t_option_spec* spec) {
	switch (spec->kind) {
		case OPTION_SET_TRUE:
		case OPTION_SET_FALSE:
			return false;
		default:
			return true;
	}
}

// 綴りを添えて弾く. 単一文字なら従来と同じ `illegal option -- Z` の形になる.
static void	report_illegal_option(const t_master* master, const char* name) {
	yoyo_dprintf(STDERR_FILENO, "%s: %s: illegal option -- %s\n",
		master->program_name, master->command_name, name);
}

static void	report_missing_argument(const t_master* master, const char* name) {
	yoyo_dprintf(STDERR_FILENO, "%s: %s: option requires an argument -- %s\n",
		master->program_name, master->command_name, name);
}

// 決まったオプションを pref に反映する. value は値を取らないオプションでは NULL.
static bool	apply_spec(
	const t_master* master,
	const t_option_spec* spec,
	void* pref,
	const char* value
) {
	void*	field = (char*)pref + spec->field_offset;
	switch (spec->kind) {
		case OPTION_SET_TRUE: {
			*(bool*)field = true;
			return true;
		}
		case OPTION_SET_FALSE: {
			*(bool*)field = false;
			return true;
		}
		case OPTION_STRING: {
			// 表に書いたフィールドは char* なので, const を外して入れる.
			// 値は argv の要素そのままで, プログラムの生存期間中は生きている.
			*(char**)field = (char*)value;
			return true;
		}
		case OPTION_UINT32: {
			uint32_t	v;
			if (parse_uint32(master, value, &v, (uint32_t)spec->min, (uint32_t)spec->max)) {
				return false;
			}
			*(uint32_t*)field = v;
			return true;
		}
		case OPTION_UINT64: {
			uint64_t	v;
			if (parse_uint64(master, value, &v, spec->min, spec->max)) {
				return false;
			}
			*(uint64_t*)field = v;
			return true;
		}
		case OPTION_CUSTOM: {
			return spec->handle(master, pref, value);
		}
	}
	return false;
}

// 1つのオプションを処理する.
// 値が要るなら *argv_ptr を1つ進めて次の引数を値に使い, *consumed_extra を1にする.
static bool	handle_one(
	const t_master* master,
	const t_option_spec* spec,
	void* pref,
	char*** argv_ptr,
	int* consumed_extra
) {
	if (!takes_value(spec)) {
		return apply_spec(master, spec, pref, NULL);
	}
	*argv_ptr += 1;
	if (**argv_ptr == NULL) {
		report_missing_argument(master, spec->name);
		return false;
	}
	*consumed_extra += 1;
	return apply_spec(master, spec, pref, **argv_ptr);
}

// 連結 (`-pq`) として解釈する.
// 先に全文字が表にあることを確かめてから反映する. 途中で見つからないときに
// 「そこまでの文字だけ適用済み」という中途半端な状態を残さないため.
static bool	handle_concatenated(
	const t_master* master,
	const char* letters,
	void* pref,
	const t_option_spec* specs,
	char*** argv_ptr,
	int* consumed_extra
) {
	for (size_t i = 0; letters[i] != '\0'; ++i) {
		const char	one[2] = { letters[i], '\0' };
		if (find_spec(specs, one) == NULL) {
			// 1文字ずつの結果ではなく元の綴りを見せる.
			// `-pubout` を md5 に渡したとき `illegal option -- u` では伝わらない.
			report_illegal_option(master, letters);
			return false;
		}
	}

	for (size_t i = 0; letters[i] != '\0'; ++i) {
		const char				one[2] = { letters[i], '\0' };
		const t_option_spec*	spec = find_spec(specs, one);
		// 値を取るオプションは末尾の1文字でなければならない.
		// 途中にあると値をどこから取るのか決まらない (従来と同じ扱い).
		if (takes_value(spec) && letters[i + 1] != '\0') {
			report_illegal_option(master, letters);
			return false;
		}
		if (!handle_one(master, spec, pref, argv_ptr, consumed_extra)) {
			return false;
		}
	}
	return true;
}

int	parse_options(const t_master* master, char** argv, void* pref, const t_option_spec* specs) {
	int	parsed_count = 0;

	while (*argv != NULL && (*argv)[0] == '-') {
		const char*	token = *argv;
		int			consumed_extra = 0;

		if (token[1] == '-') {
			// "--name": 名前として引くだけ. 連結にはしない
			// (`--pq` を `-p -q` と読むのは筋が通らない)
			const t_option_spec*	spec = find_spec(specs, token + 2);
			if (spec == NULL) {
				report_illegal_option(master, token + 2);
				return -1;
			}
			if (!handle_one(master, spec, pref, &argv, &consumed_extra)) {
				return -1;
			}
		} else {
			// "-name": まず綴り全体を引き, 引けなければ連結として試す
			const t_option_spec*	spec = find_spec(specs, token + 1);
			if (spec != NULL) {
				if (!handle_one(master, spec, pref, &argv, &consumed_extra)) {
					return -1;
				}
			} else if (!handle_concatenated(master, token + 1, pref, specs, &argv, &consumed_extra)) {
				return -1;
			}
		}

		argv += 1;
		parsed_count += 1 + consumed_extra;
	}
	return parsed_count;
}
