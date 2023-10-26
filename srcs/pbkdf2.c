#include "ft_ssl.h"
#include "generic_message.h"

t_generic_message	salt_i(
	const t_generic_message* salt,
	uint32_t i
) {
	t_generic_message si = dup_generic_message(salt);
	if (is_failed_generic_message(&si)) {
		return FAILED_GENERIC_MESSAGE;
	}

	if (is_little_endian()) {
		i = SWAP_BYTE(i);
	}
	t_generic_message	gi = {
		.byte_size = sizeof(i),
		.message = &i,
	};
	if (!join_assign_generic_message(&si, &gi)) {
		destroy_generic_message(&si);
		return FAILED_GENERIC_MESSAGE;
	}
	return si;
}

t_generic_message	f(
	const t_pbkdf2_prf* prf,
	const t_generic_message* password,
	const t_generic_message* salt,
	size_t c,
	size_t i
) {
	assert(c >= 1);

	t_generic_message	u = salt_i(salt, i);
	if (is_failed_generic_message(&u)) {
		return FAILED_GENERIC_MESSAGE;
	}
	yoyo_dprintf(STDOUT_FILENO, "u0: \t"); print_generic_message_hex(&u, STDOUT_FILENO); yoyo_dprintf(STDOUT_FILENO, "\n"); 
	t_generic_message t = new_generic_message(prf->hlen);
	if (is_failed_generic_message(&t)) {
		destroy_generic_message(&u);
		return FAILED_GENERIC_MESSAGE;
	}
	for (uint32_t i = 1; i < c; ++i) {
		DEBUGOUT("|u|: \t%zu", u.byte_size);
		t_generic_message next_u = prf->func(password, &u);
		if (is_failed_generic_message(&next_u)) {
			destroy_generic_message(&u);
			return FAILED_GENERIC_MESSAGE;
		}
		yoyo_dprintf(STDOUT_FILENO, "u%u: \t", i); print_generic_message_hex(&next_u, STDOUT_FILENO); yoyo_dprintf(STDOUT_FILENO, "\n"); 
		DEBUGOUT("hlen of %s = %zu, |t| = %zu, |next_u| = %zu", prf->name, prf->hlen, t.byte_size, next_u.byte_size);
		xor_assign_generic_message(&t, &next_u);
		u = next_u;
		yoyo_dprintf(STDOUT_FILENO, "t: \t"); print_generic_message_hex(&t, STDOUT_FILENO); yoyo_dprintf(STDOUT_FILENO, "\n"); 
	}

	return t;
}

t_generic_message	pbkdf2(
	const t_pbkdf2_prf* prf,
	const t_generic_message* password,
	const t_generic_message* salt,
	size_t c,
	size_t dklen
) {

	if (c < 1) {
		DEBUGERR("c is too small: %zu", c);
		return FAILED_GENERIC_MESSAGE;
	}
	if (dklen < 1) {
		DEBUGERR("dklen is too small: %zu", dklen);
		return FAILED_GENERIC_MESSAGE;
	}

	if (dklen > ((1ull << 32) - 1) * prf->hlen) {
		DEBUGERR("w is too big: dklen: %zu, hlen: %zu", dklen, prf->hlen);
		return FAILED_GENERIC_MESSAGE;
	}
	const size_t	w = (dklen - 1) / prf->hlen + 1;
	assert(w <= ((1ull << 32) - 1));

	t_generic_message	dk = new_generic_message(0);
	if (is_failed_generic_message(&dk)) {
		DEBUGERR("failed to allocate memory for dk: dklen: %zu", dklen);
		return FAILED_GENERIC_MESSAGE;
	}
	for (size_t i = 1; i <= w; ++i) {
		t_generic_message	t = f(prf, password, salt, c, i);
		if (is_failed_generic_message(&t)) {
			destroy_generic_message(&dk);
			return FAILED_GENERIC_MESSAGE;
		}
		yoyo_dprintf(STDOUT_FILENO, "t%zu: \t", i); print_generic_message_hex(&t, STDOUT_FILENO); yoyo_dprintf(STDOUT_FILENO, "\n");
		if (!join_assign_generic_message(&dk, &t)) {
			destroy_generic_message(&t);
			destroy_generic_message(&dk);
			return FAILED_GENERIC_MESSAGE;
		}
		destroy_generic_message(&t);
	}
	assert(dk.byte_size >= dklen);
	if (dk.byte_size > dklen) {
		DEBUGOUT("dk truncation: %zu -> %zu", dk.byte_size, dklen);
		dk.byte_size = dklen;
	}
	DEBUGINFO("dklen: %zu, hlen: %zu, w: %zu", dklen, prf->hlen, w);

	return dk;
}

int	run_pbkdf2(t_master* master, char **argv) {
	// usage:
	// ./ft_ssl pbkdf2 [-a algorithm_name] [-s salt_path] [-S salt_str] [password_path]
	t_master_hmac	m = {
		.master = *master,
	};

	t_preference*	pref = &m.pref;
	int parsed_count = parse_options_pbkdf2(master, argv, pref);
	if (parsed_count < 0) {
		return 1;
	}
	argv += parsed_count;

	if (pref->path_salt == NULL && pref->message_argument == NULL) {
		pref->message_argument = "";
	}

	t_generic_message	salt = pref->path_salt == NULL
		? new_generic_message_str(&m.master, pref->message_argument)
		: new_generic_message_path(&m.master, pref->path_salt);
	if (is_failed_generic_message(&salt)) {
		PRINT_ERROR(master, "failed to read salt\n", "");
		return 1;
	}
	DEBUGINFO("salt size: %zu", salt.byte_size);	

	t_generic_message	password;
	if (*argv == NULL) {
		password = new_generic_message_stdin(&m.master);
	} else {
		DEBUGOUT("read password from path: %s", *argv);
		password = new_generic_message_path(&m.master, *argv);
	}
	if (is_failed_generic_message(&password)) {
		destroy_generic_message(&salt);
		return 1;
	}
	DEBUGINFO("password size: %zu", password.byte_size);

	t_generic_message	dk =  pbkdf2(pref->prf, &password, &salt, 100, 300);
	if (dk.message != NULL) {
		print_generic_message_hex(&dk, STDOUT_FILENO);
		yoyo_dprintf(STDOUT_FILENO, "\n");
	}

	destroy_generic_message(&salt);
	destroy_generic_message(&password);
	destroy_generic_message(&dk);

	(void)m;
	(void)argv;
	return 0;
}