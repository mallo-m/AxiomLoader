#include "AxiomLoader.h"

const char* drunk_strdup(const char* str)
{
	char* res;
	char* cursor;

	if (str == (NULL))
		return (NULL);
	cursor = res = (char*)malloc(sizeof(char) + strlen(str) + 1);
	if (cursor == NULL)
		return (NULL);
	while (*str != '\0')
		*cursor++ = *str++;
	*cursor = '\0';
	return (res);
}

const int drunk_strcmp(const char* s1, const char* s2)
{
	int i;

	i = 0;
	while (s1[i] == s2[i] && i < strlen(s1) && i < strlen(s2))
		i++;

	return (s1[i] - s2[i]);
}

unsigned char* drunk_memcpy(unsigned char* dest, const unsigned char* src, size_t len)
{
	size_t counter;

	counter = 0;
	if (src == NULL || dest == NULL)
		return (NULL);
	while (counter < len)
	{
		dest[counter] = src[counter];
		counter++;
	}
	return (dest);
}
