#include "ft_ssl.h"

t_lst		*new_element(void *content)
{
	t_lst	*new;

	new = malloc(sizeof(t_lst));
	if (!new)
		return (NULL);
	new->content = content;
	new->next = NULL;
	return (new);
}

t_lst		*add_list(t_lst **lst, void *content)
{
	if (!(*lst))
	{
		*lst = new_element(content);
		return (*lst);
	}
	else
	{
		t_lst *tmp;

		tmp = *lst;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = new_element(content);
		return (tmp->next);
	}
}

void		clear_list(t_lst *lst)
{
	t_lst *tmp;
	t_lst *next;

	tmp = lst;
	while (tmp)
	{
		next = tmp->next;
		free(tmp);
		tmp = next;
	}
}
