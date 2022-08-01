_RED		=	\e[31m
_GREEN		=	\e[32m
_YELLOW		=	\e[33m
_BLUE		=	\e[34m
_END		=	\e[0m

CC			=	gcc
CC_FLAGS	=	-Wall -Wextra -Werror -fno-builtin

DIR_HEADERS		=	./includes/
DIR_SRCS		=	./srcs/
DIR_OBJS		=	./compiled_srcs/
DIR_TESTS		=	./tests/

SRCS			=	ft_ssl.c \
					opt_arg.c \
					args.c \
					logs.c \
					utils.c \
					hash/process.c \
					hash/md5.c \
					hash/sha256.c \
					hash/sha224.c \
					hash/sha512.c \
					hash/sha384.c \
					cipher/process.c \
					cipher/base64.c \
					cipher/des-ecb.c \
					cipher/des-cbc.c

INCLUDES		=	ft_ssl.h \
					cipher.h \
					hash.h \
					error.h

OBJS 		=	$(SRCS:%.c=$(DIR_OBJS)%.o)
DEPS 		=	$(SRCS:%.c=$(DIR_OBJS)%.d)
NAME 		=	ft_ssl

LIB			=	libft_ssl.a

ifeq ($(BUILD),debug)
	CC_FLAGS		+=	-DDEBUG -g3 -fsanitize=address
	DIR_OBJS		=	./debug-compiled_srcs/
	NAME			=	./debug-ft_ssl
endif

all:			$(NAME)

test:			$(NAME) #$(LIB)
#				@make -C $(DIR_TESTS)
#				@printf "\033[2K\r$(_BLUE)Testing Library... $(_END)\n"
#				$(DIR_TESTS)ftest_ssl
				@printf "\033[2K\r$(_BLUE)Testing Executable... $(_END)\n"
				$(DIR_TESTS)test_script.sh

$(LIB):			$(OBJS) $(addprefix $(DIR_HEADERS), $(INCLUDES))
				@printf "\033[2K\r$(_BLUE) All files compiled into '$(DIR_OBJS)'. $(_END)✅\n"
				@ar rc $(LIB) $(OBJS)
				@ranlib $(LIB)
				@printf "\033[2K\r$(_GREEN) Library '$(LIB)' created. $(_END)✅\n"

$(NAME):		$(OBJS) $(addprefix $(DIR_HEADERS), $(INCLUDES))
				@printf "\033[2K\r$(_BLUE) All files compiled into '$(DIR_OBJS)'. $(_END)✅\n"
				@$(CC) $(CC_FLAGS) -I $(DIR_HEADERS) $(OBJS) -o $(NAME) -lm
				@printf "\033[2K\r$(_GREEN) Executable '$(NAME)' created. $(_END)✅\n"

$(OBJS):		| $(DIR_OBJS)

$(DIR_OBJS)%.o: $(DIR_SRCS)%.c Makefile # Recompile if Makefile change
				@mkdir -p $(dir $@)
				@printf "\033[2K\r $(_YELLOW)Compiling $< $(_END)⌛ "
				@$(CC) $(CC_FLAGS) -MMD -MP -I $(DIR_HEADERS) -c $< -o $@
-include		$(DEPS)

$(DIR_OBJS):
				@mkdir -p $(DIR_OBJS)

clean:
				@rm -rf $(DIR_OBJS)
				@printf "\033[2K\r$(_RED) '"$(DIR_OBJS)"' has been deleted. $(_END)🗑️\n"

fclean:			clean
				@make fclean -C $(DIR_TESTS)
				@rm -rf $(LIB)
				@printf "\033[2K\r$(_RED) '"$(LIB)"' has been deleted. $(_END)🗑️\n"
				@rm -rf $(NAME)
				@printf "\033[2K\r$(_RED) '"$(NAME)"' has been deleted. $(_END)🗑️\n"

re:				fclean
				@$(MAKE) --no-print-directory

.PHONY:			all clean fclean re test
