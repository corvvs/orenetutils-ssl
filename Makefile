SRCDIR	:=	srcs
OBJDIR	:=	objs
INCDIR	:=	includes
FILES	:=	\
			main.c\
			md5.c\
			md5_block_padding.c\
			md5_block_rounds.c\
			md5_derive_digest.c\
			sha_2.c\
			sha_256_block_padding.c\
			sha_256_block_rounds.c\
			sha_256_derive_digest.c\
			subbyte_manipulation.c\
			utils_endian.c\

SRCS	:=	$(FILES:%.c=$(SRCDIR)/%.c)
OBJS	:=	$(FILES:%.c=$(OBJDIR)/%.o)
NAME	:=	ft_ssl

LIBFT		:=	libft.a
LIBFT_DIR	:=	libft
CC			:=	gcc
CCOREFLAGS	=	-Wall -Wextra -Werror -I$(INCDIR) -I$(LIBFT_DIR)
CFLAGS		=	$(CCOREFLAGS)\
				-D DEBUG\
				-g -fsanitize=address -fsanitize=undefined\

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

.PHONY:	test_md5 test_sha_256
test_md5: $(NAME)
	bash test/md5_simple.sh ""
	bash test/md5_simple.sh "h"
	bash test/md5_simple.sh "he"
	bash test/md5_simple.sh "hel"
	bash test/md5_simple.sh "hell"
	bash test/md5_simple.sh "hello"
	bash test/md5_simple.sh "hello!"
	bash test/md5_simple.sh "974906r9065098t6089569067062078y78yf97t80o7t0o10to8hrr7hgf0o78t872t587f2578fy8gor875boxd9ygn3d098ygbg8on63hcrbuchnyrouifxr7bgoy78b897b8oao78yb789y789bo29n578yo5y89o"

test_sha_256: $(NAME)
	bash test/sha_256_simple.sh ""
	bash test/sha_256_simple.sh "h"
	bash test/sha_256_simple.sh "he"
	bash test/sha_256_simple.sh "hel"
	bash test/sha_256_simple.sh "hell"
	bash test/sha_256_simple.sh "hello"
	bash test/sha_256_simple.sh "hello!"
	bash test/sha_256_simple.sh "974906r9065098t6089569067062078y78yf97t80o7t0o10to8hrr7hgf0o78t872t587f2578fy8gor875boxd9ygn3d098ygbg8on63hcrbuchnyrouifxr7bgoy78b897b8oao78yb789y789bo29n578yo5y89o"

.PHONY:	up
up:
	docker-compose up --build -d

.PHONY:	down
down:
	docker-compose down

.PHONY:	it
it:
	docker-compose exec app bash
