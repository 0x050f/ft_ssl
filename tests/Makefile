_RED		=	\e[31m
_GREEN		=	\e[32m
_YELLOW		=	\e[33m
_BLUE		=	\e[34m
_END		=	\e[0m

CC			=	gcc
CC_FLAGS	=	-Wall -Wextra -Werror

DIR_HEADERS		=	includes/
DIR_SRCS		=	srcs/
DIR_OBJS		=	compiled_srcs/

SRCS			=	main.c \
					check_hmac_sha256.c \
					check_pbkdf2_sha256.c

INCLUDES		=	tests.h

OBJS 		=	$(SRCS:%.c=$(DIR_OBJS)%.o)
DEPS 		=	$(SRCS:%.c=$(DIR_OBJS)%.d)
NAME 		=	ftest_ssl

all:			$(NAME)

$(NAME):		$(OBJS) $(addprefix $(DIR_HEADERS), $(INCLUDES))
				@printf "\033[2K\r$(_BLUE) All files compiled into '$(DIR_OBJS)'. $(_END)✅\n"
				@$(CC) $(CC_FLAGS) -L.. -I $(DIR_HEADERS) -I../$(DIR_HEADERS) $(OBJS) -lft_ssl -lcheck -lm -lpthread -lrt -lsubunit -o $(NAME)
				@printf "\033[2K\r$(_GREEN) Executable '$(NAME)' created. $(_END)✅\n"

$(OBJS):		| $(DIR_OBJS)

$(DIR_OBJS)%.o: $(DIR_SRCS)%.c Makefile # Recompile if Makefile change
				@mkdir -p $(dir $@)
				@printf "\033[2K\r $(_YELLOW)Compiling $< $(_END)⌛ "
				@$(CC) $(CC_FLAGS) -MMD -MP -I $(DIR_HEADERS) -I../$(DIR_HEADERS) -c $< -o $@
-include		$(DEPS)

$(DIR_OBJS):
				@mkdir -p $(DIR_OBJS)

clean:
				@rm -rf $(DIR_OBJS)
				@printf "\033[2K\r$(_RED) '"$(DIR_OBJS)"' has been deleted. $(_END)🗑️\n"

fclean:			clean
				@rm -rf $(LIB)
				@printf "\033[2K\r$(_RED) '"$(LIB)"' has been deleted. $(_END)🗑️\n"
				@rm -rf $(NAME)
				@printf "\033[2K\r$(_RED) '"$(NAME)"' has been deleted. $(_END)🗑️\n"

re:				fclean
				@$(MAKE) --no-print-directory

.PHONY:			all clean fclean re
