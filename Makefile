SRCDIR	:=	srcs
OBJDIR	:=	objs
INCDIR	:=	includes
FILES	:=	\
			main.c\
			repl.c\
			preference.c\
			md5.c\
			md5_block_padding.c\
			md5_block_rounds.c\
			md5_derive_digest.c\
			sha_224.c\
			sha_224_block_padding.c\
			sha_224_block_rounds.c\
			sha_224_derive_digest.c\
			sha_256.c\
			sha_256_block_padding.c\
			sha_256_block_rounds.c\
			sha_256_derive_digest.c\
			sha_384.c\
			sha_384_block_padding.c\
			sha_384_block_rounds.c\
			sha_384_derive_digest.c\
			sha_512.c\
			sha_512_block_padding.c\
			sha_512_block_rounds.c\
			sha_512_derive_digest.c\
			sha_512_224.c\
			sha_512_224_block_padding.c\
			sha_512_224_block_rounds.c\
			sha_512_224_derive_digest.c\
			sha_512_256.c\
			sha_512_256_block_padding.c\
			sha_512_256_block_rounds.c\
			sha_512_256_derive_digest.c\
			base64.c\
			base64_encode.c\
			base64_decode.c\
			base64_preference.c\
			hmac.c\
			hmac_digest_interface.c\
			hmac_frontend.c\
			hmac_preference.c\
			generic_message.c\
			generic_message_io.c\
			subbyte_manipulation.c\
			read_file.c\
			run_command.c\
			run_digest_helper.c\
			elastic_buffer.c\
			elastic_buffer_helper.c\
			utils_endian.c\
			utils_error.c\
			utils_print.c\
			printf.c\
			test.c\

SRCS	:=	$(FILES:%.c=$(SRCDIR)/%.c)
OBJS	:=	$(FILES:%.c=$(OBJDIR)/%.o)
NAME	:=	ft_ssl

LIBFT		:=	libft.a
LIBFT_DIR	:=	libft
CC			:=	gcc
CCOREFLAGS	=	-Wall -Wextra -Werror -I$(INCDIR) -I$(LIBFT_DIR)
CFLAGS		=	$(CCOREFLAGS)\
				-g -fsanitize=address -fsanitize=undefined\
				-O2 \
				-D DEBUG

RM			:=	rm -rf

all:			$(NAME)


$(OBJDIR)/%.o:	$(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o:	%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME):	$(OBJS) $(LIBFT)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS) $(LIBFT)

$(LIBFT):
	$(MAKE) -C $(LIBFT_DIR)
	cp $(LIBFT_DIR)/$(LIBFT) .

.PHONY:	clean
clean:
	$(RM) $(OBJDIR) $(LIBFT)

.PHONY:	fclean
fclean:			clean
	$(RM) $(LIBFT) $(NAME)
	$(MAKE) -C $(LIBFT_DIR) fclean

.PHONY:	re
re:				fclean all

.PHONY: test_algos test_md5 test_sha_224 test_sha_256 test_sha_384 test_sha_512 test_sha_512_224 test_sha_512_256

test_algos: $(NAME) test_md5 test_sha_224 test_sha_256 test_sha_384 test_sha_512 test_sha_512_224 test_sha_512_256

test_md5: $(NAME)
	bash test/md5_simple.sh ""
	bash test/md5_simple.sh "h"
	bash test/md5_simple.sh "he"
	bash test/md5_simple.sh "hel"
	bash test/md5_simple.sh "hell"
	bash test/md5_simple.sh "hello"
	bash test/md5_simple.sh "hello!"
	bash test/md5_simple.sh "974906r9065098t6089569067062078y78yf97t80o7t0o10to8hrr7hgf0o78t872t587f2578fy8gor875boxd9ygn3d098ygbg8on63hcrbuchnyrouifxr7bgoy78b897b8oao78yb789y789bo29n578yo5y89o"

test_sha_224: $(NAME)
	bash test/sha_224_simple.sh ""
	bash test/sha_224_simple.sh "h"
	bash test/sha_224_simple.sh "he"
	bash test/sha_224_simple.sh "hel"
	bash test/sha_224_simple.sh "hell"
	bash test/sha_224_simple.sh "hello"
	bash test/sha_224_simple.sh "hello!"
	bash test/sha_224_simple.sh "974906r9065098t6089569067062078y78yf97t80o7t0o10to8hrr7hgf0o78t872t587f2578fy8gor875boxd9ygn3d098ygbg8on63hcrbuchnyrouifxr7bgoy78b897b8oao78yb789y789bo29n578yo5y89o"

test_sha_256: $(NAME)
	bash test/sha_256_simple.sh ""
	bash test/sha_256_simple.sh "h"
	bash test/sha_256_simple.sh "he"
	bash test/sha_256_simple.sh "hel"
	bash test/sha_256_simple.sh "hell"
	bash test/sha_256_simple.sh "hello"
	bash test/sha_256_simple.sh "hello!"
	bash test/sha_256_simple.sh "974906r9065098t6089569067062078y78yf97t80o7t0o10to8hrr7hgf0o78t872t587f2578fy8gor875boxd9ygn3d098ygbg8on63hcrbuchnyrouifxr7bgoy78b897b8oao78yb789y789bo29n578yo5y89o"

test_sha_384: $(NAME)
	bash test/sha_384_simple.sh ""
	bash test/sha_384_simple.sh "h"
	bash test/sha_384_simple.sh "he"
	bash test/sha_384_simple.sh "hel"
	bash test/sha_384_simple.sh "hell"
	bash test/sha_384_simple.sh "hello"
	bash test/sha_384_simple.sh "hello!"
	bash test/sha_384_simple.sh "974906r9065098t6089569067062078y78yf97t80o7t0o10to8hrr7hgf0o78t872t587f2578fy8gor875boxd9ygn3d098ygbg8on63hcrbuchnyrouifxr7bgoy78b897b8oao78yb789y789bo29n578yo5y89o"

test_sha_512: $(NAME)
	bash test/sha_512_simple.sh ""
	bash test/sha_512_simple.sh "h"
	bash test/sha_512_simple.sh "he"
	bash test/sha_512_simple.sh "hel"
	bash test/sha_512_simple.sh "hell"
	bash test/sha_512_simple.sh "hello"
	bash test/sha_512_simple.sh "hello!"
	bash test/sha_512_simple.sh "974906r9065098t6089569067062078y78yf97t80o7t0o10to8hrr7hgf0o78t872t587f2578fy8gor875boxd9ygn3d098ygbg8on63hcrbuchnyrouifxr7bgoy78b897b8oao78yb789y789bo29n578yo5y89o"

test_sha_512_224: $(NAME)
	bash test/sha_512_224_simple.sh ""
	bash test/sha_512_224_simple.sh "h"
	bash test/sha_512_224_simple.sh "he"
	bash test/sha_512_224_simple.sh "hel"
	bash test/sha_512_224_simple.sh "hell"
	bash test/sha_512_224_simple.sh "hello"
	bash test/sha_512_224_simple.sh "hello!"
	bash test/sha_512_224_simple.sh "974906r9065098t6089569067062078y78yf97t80o7t0o10to8hrr7hgf0o78t872t587f2578fy8gor875boxd9ygn3d098ygbg8on63hcrbuchnyrouifxr7bgoy78b897b8oao78yb789y789bo29n578yo5y89o"

test_sha_512_256: $(NAME)
	bash test/sha_512_256_simple.sh ""
	bash test/sha_512_256_simple.sh "h"
	bash test/sha_512_256_simple.sh "he"
	bash test/sha_512_256_simple.sh "hel"
	bash test/sha_512_256_simple.sh "hell"
	bash test/sha_512_256_simple.sh "hello"
	bash test/sha_512_256_simple.sh "hello!"
	bash test/sha_512_256_simple.sh "974906r9065098t6089569067062078y78yf97t80o7t0o10to8hrr7hgf0o78t872t587f2578fy8gor875boxd9ygn3d098ygbg8on63hcrbuchnyrouifxr7bgoy78b897b8oao78yb789y789bo29n578yo5y89o"

PHONY: test_pdf
test_pdf: $(NAME)
	@bash test/pdf_test.sh md5
	@bash test/pdf_test.sh sha224
	@bash test/pdf_test.sh sha256
	@bash test/pdf_test.sh sha384
	@bash test/pdf_test.sh sha512
	@bash test/pdf_test.sh sha512-224
	@bash test/pdf_test.sh sha512-256

PHONY: test_hmac
test_hmac:
	@ruby test/hmac.rb

.PHONY:	up
up:
	docker-compose up --build -d

.PHONY:	down
down:
	docker-compose down

.PHONY:	it
it:
	docker-compose exec app bash
