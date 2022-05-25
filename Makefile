_RED		=	\e[31m
_GREEN		=	\e[32m
_YELLOW		=	\e[33m
_BLUE		=	\e[34m
_END		=	\e[0m

CC_FLAGS	=	-Wall -Wextra -Werror -fno-builtin

DIR_HEADERS		=	./includes/
DIR_SRCS		=	./srcs/
DIR_OBJS		=	./compiled_srcs/

SRCS			=	ft_ssl.c \
					args.c \
					lst.c \
					logs.c \
					utils.c \
					hash/md5.c \
					hash/sha256.c \
					hash/sha224.c \
					hash/sha512.c \
					hash/sha384.c

INCLUDES		=	ft_ssl.h

OBJS 		=	$(SRCS:%.c=$(DIR_OBJS)%.o)
NAME 		=	ft_ssl

ifeq ($(BUILD),debug)
	CC_FLAGS		+=	-DDEBUG -g3 -fsanitize=address
	DIR_OBJS		=	./debug-compiled_srcs/
	NAME			=	./debug-ft_ssl
endif

all:			$(NAME)

$(NAME):		$(OBJS) $(addprefix $(DIR_HEADERS), $(INCLUDES))
				@printf "\033[2K\r$(_BLUE) All files compiled into '$(DIR_OBJS)'. $(_END)✅\n"
				@gcc $(CC_FLAGS) -I $(DIR_HEADERS) $(OBJS) -o $(NAME)
				@printf "\033[2K\r$(_GREEN) Executable '$(NAME)' created. $(_END)✅\n"

$(OBJS):		| $(DIR_OBJS)

$(DIR_OBJS)%.o: $(DIR_SRCS)%.c
				@mkdir -p $(dir $@)
				@printf "\033[2K\r $(_YELLOW)Compiling $< $(_END)⌛ "
				@gcc $(CC_FLAGS) -I $(DIR_HEADERS) -c $< -o $@

$(DIR_OBJS):
				@mkdir -p $(DIR_OBJS)

clean:
ifneq (,$(wildcard $(DIR_OBJS)))
				@rm -rf $(DIR_OBJS)
				@printf "\033[2K\r$(_RED) '"$(DIR_OBJS)"' has been deleted. $(_END)🗑️\n"
endif

fclean:			clean
ifneq (,$(wildcard $(NAME)))
				@rm -rf $(NAME)
				@printf "\033[2K\r$(_RED) '"$(NAME)"' has been deleted. $(_END)🗑️\n"
endif

re:				fclean
				@$(MAKE) --no-print-directory

.PHONY:			all clean fclean re
