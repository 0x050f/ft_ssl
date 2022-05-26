#include "ft_ssl.h"

t_opt_arg		*new_opt_arg(char arg, void *content)
{
	t_opt_arg	*new;

	new = malloc(sizeof(t_opt_arg));
	if (!new)
		return (NULL);
	new->arg = arg;
	new->content = content;
	new->next = NULL;
	return (new);
}

t_opt_arg		*append_opt_arg(t_opt_arg **opt_args, char arg, void *content)
{
	if (!(*opt_args))
	{
		*opt_args = new_opt_arg(arg, content);
		return (*opt_args);
	}
	else
	{
		t_opt_arg *tmp;

		tmp = *opt_args;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = new_opt_arg(arg, content);
		return (tmp->next);
	}
}

t_opt_arg	*get_last_arg(t_opt_arg *opt_args, char arg)
{
	t_opt_arg *tmp;
	t_opt_arg *res = NULL;

	tmp = opt_args;
	while (tmp)
	{
		if (tmp->arg == arg)
			res = tmp;
		tmp = tmp->next;
	}
	return (res);
}

void		*get_last_content(t_opt_arg *opt_args, char arg)
{
	t_opt_arg	*opt = get_last_arg(opt_args, arg);
	if (!opt)
		return (NULL);
	return (opt->content);
}

void		clear_opt_arg(t_opt_arg *opt_args)
{
	t_opt_arg *tmp;
	t_opt_arg *next;

	tmp = opt_args;
	while (tmp)
	{
		next = tmp->next;
		free(tmp);
		tmp = next;
	}
}
