#include "ft_ssl.h"

#define define_generic_message_literal(data) \
	(t_generic_message){ \
		.message = (void*)data, \
		.byte_size = sizeof(data) - 1, \
	}

// https://www.nic.ad.jp/ja/tech/ipa/RFC2202JA.html

// test_case =     1
// key =           0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
// key_len =       16
// data =          "Hi There"
// data_len =      8
// digest =        0x9294727a3638bb1c13f48ef8158bfc9d
void	md5_1(void) {
	char	kb[17];
	ft_memset(kb, 0x0b, sizeof(kb) - 1);
	const t_generic_message key = define_generic_message_literal(kb);
	const t_generic_message data = define_generic_message_literal("Hi There");
	hmac_md5(&key, &data);
}

// test_case =     2
// key =           "Jefe"
// key_len =       4
// data =          "what do ya want for nothing?"
// data_len =      28
// digest =        0x750c783e6ab0b503eaa86e310a5db738
void	md5_2(void) {
	const t_generic_message key = define_generic_message_literal("Jefe");
	const t_generic_message data = define_generic_message_literal("what do ya want for nothing?");
	hmac_md5(&key, &data);
}

// test_case =     3
// key =           0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
// key_len         16
// data =          0xdd を 50 回繰り返す
// data_len =      50
// digest =        0x56be34521d144c88dbb8c733f0e8b3f6
void	md5_3(void) {
	char	kb[17];
	ft_memset(kb, 0xaa, sizeof(kb) - 1);
	char	db[51];
	ft_memset(db, 0xdd, sizeof(db) - 1);
	const t_generic_message key = define_generic_message_literal(kb);
	const t_generic_message data = define_generic_message_literal(db);
	hmac_md5(&key, &data);
}

// test_case =     4
// key =           0x0102030405060708090a0b0c0d0e0f10111213141516171819
// key_len         25
// data =          0xcd を 50 回繰り返す
// data_len =      50
// digest =        0x697eaf0aca3a3aea3a75164746ffaa79
void	md5_4(void) {
	char	kb[26];
	for (size_t i = 0; i < sizeof(kb) - 1; i++) {
		kb[i] = i + 1;
	}
	char	db[51];
	ft_memset(db, 0xcd, sizeof(db) - 1);
	const t_generic_message key = define_generic_message_literal(kb);
	const t_generic_message data = define_generic_message_literal(db);
	hmac_md5(&key, &data);
}

// test_case =     5
// key =           0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
// key_len =       16
// data =          "Test With Truncation"
// data_len =      20
// digest =        0x56461ef2342edc00f9bab995690efd4c
// digest-96       0x56461ef2342edc00f9bab995
void	md5_5(void) {
	char	kb[17];
	ft_memset(kb, 0x0c, sizeof(kb) - 1);
	const t_generic_message key = define_generic_message_literal(kb);
	const t_generic_message data = define_generic_message_literal("Test With Truncation");
	hmac_md5(&key, &data);
}

// test_case =     6
// key =           0xaa を 80 回繰り返す
// key_len =       80
// data =          "Test Using Larger Than Block-Size Key - Hash Key First"
// data_len =      54
// digest =        0x6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd
void	md5_6(void) {
	char	kb[81];
	ft_memset(kb, 0xaa, sizeof(kb) - 1);
	const t_generic_message key = define_generic_message_literal(kb);
	const t_generic_message data = define_generic_message_literal("Test Using Larger Than Block-Size Key - Hash Key First");
	hmac_md5(&key, &data);
}

// test_case =     7
// key =           0xaa を 80 回繰り返す
// key_len =       80
// data =          "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
// data_len =      73
// digest =        0x6f630fad67cda0ee1fb1f562db3aa53e
void	md5_7(void) {
	char	kb[81];
	ft_memset(kb, 0xaa, sizeof(kb) - 1);
	const t_generic_message key = define_generic_message_literal(kb);
	const t_generic_message data = define_generic_message_literal("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data");
	hmac_md5(&key, &data);
}

void	run_cases_md5(void) {
	md5_1();
	md5_2();
	md5_3();
	md5_4();
	md5_5();
	md5_6();
	md5_7();
}

int	run_test(t_master* master, char **argv) {
	(void)master;
	(void)argv;

	// const t_generic_message key = {
	// 	.message = "Jefe",
	// 	.byte_size = 4,
	// };
	// const t_generic_message plain = {
	// 	.message = "what do ya want for nothing?",
	// 	.byte_size = 28,
	// };

	run_cases_md5();

	return 1;
}
