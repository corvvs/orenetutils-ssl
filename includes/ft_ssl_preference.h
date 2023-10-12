#ifndef FT_SSL_PREFERENCE_H
#define FT_SSL_PREFERENCE_H

#define PARSE_PREFERENCE_WITH_1_ARGUMENT(opt_char, opt, field)                              \
	case opt_char:                                                                   \
	{                                                                             \
		/* option に後続がある場合はアウト */                         \
		if (option[1])                                                            \
		{                                                                         \
			print_error_by_message(master, "illegal option -- " #opt "\n");       \
			return -1;                                                            \
		}                                                                         \
		/* argv に後続がない場合はアウト */                           \
		argv += 1;                                                                \
		if (*argv == NULL)                                                        \
		{                                                                         \
			print_error_by_message(master, "option requires an argument -- s\n"); \
			return -1;                                                            \
		}                                                                         \
		pref.field = *argv;                                                       \
		parsed_count += 1;                                                        \
		break;                                                                    \
	}

#endif
