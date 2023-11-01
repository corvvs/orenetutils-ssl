#ifndef OPTION_PARSER_H
#define OPTION_PARSER_H

#include "ft_ssl_structure.h"

#define PICK_ONE_ARG \
	if (*(arg + 1)) {\
		++arg;\
	} else {\
		PICK_NEXT_ARG;\
		arg = **argv;\
	}\

#define PARSE_NUMBER_SOPT(ch, _, store, min, max) case ch: {\
	PICK_ONE_ARG;\
	unsigned long rv;\
	if (parse_number(arg, &rv, min, max)) {\
		return -1;\
	}\
	EXHAUST_ARG;\
	store = rv;\
	break;\
}

int parse_uint32(const t_master* m, const char* str, uint32_t* out, uint32_t min, uint32_t max);
int parse_uint64(const t_master* m, const char* str, uint64_t* out, uint64_t min, uint64_t max);

int parse_number(
	const t_master* m,
	const char* str,
	unsigned long* out,
	unsigned long min,
	unsigned long max
);

int	parse_pattern(
	const t_master* m,
	const char* str,
	char* buffer,
	size_t max_len
);

#endif
