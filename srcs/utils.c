#include "ft_ssl.h"

size_t		ft_strlen_special(char *str, size_t max)
{
	size_t i;

	i = 0;
	while (i < max && str[i] >= ' ' && str[i] <= '~')
		i++;
	return (i);
}

void		ft_toupper(char *str)
{
	size_t i;

	i = 0;
	while (str[i])
	{
		if (str[i] >= 'a' && str[i] <= 'z')
			str[i] -= 'a' - 'A';
		i++;
	}
}

int			ishexa(char *str)
{
	size_t i;

	i = 0;
	while (str[i])
	{
		if (!((str[i] >= 'a' && str[i] <= 'f') || (str[i] >= 'A' && str[i] <= 'F') || (str[i] >= '0' && str[i] <= '9')))
			return (0);
		i++;
	}
	return (1);
}

int			isprintable(char *str)
{
	size_t i;

	i = 0;
	while (str[i])
	{
		if (str[i] < 32 || str[i] > 126)
			return (0);
		i++;
	}
	return (1);
}
