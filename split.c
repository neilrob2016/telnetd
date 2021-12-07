#include "globals.h"


/*** Split a string into individual words. Takes account of quotes. ***/
char *splitString(char *str, char *end, char ***words, int *word_cnt)
{
	char *ptr;
	char *start = NULL;
	char quotes = 0;
	char c;

	*words = NULL;
	*word_cnt = 0;

	for(ptr=str;(!end || ptr < end) && *ptr && *ptr != '\n';++ptr)
	{
		c = *ptr;
		if (c == '"' || c == '\'')
		{
			if (quotes == c)
			{
				addWordToArray(words,start,ptr,word_cnt);
				quotes = 0;
				start = NULL;
				continue;
			}
			if (quotes) continue;

			if (start) addWordToArray(words,start,ptr,word_cnt);
			quotes = c;
			start = ptr+1;
			continue;
		}
		if (quotes) continue;

		if (c < 33)
		{
			if (start)
			{
				addWordToArray(words,start,ptr,word_cnt);
				start = NULL;
			}
		}
		else if (c == '#') break;
		else if (!start) start = ptr;
	}
	if (quotes)
	{
		/* Missing end quotes */
		*word_cnt = -1;
		return NULL;
	}

	if (start) addWordToArray(words,start,ptr,word_cnt);
	if (*word_cnt) (*words)[*word_cnt] = NULL;
	return ptr;
}




void addWordToArray(char ***words, char *word, char *end, int *word_cnt)
{
	char c;

	if (end)
	{
 		c = *end;
		*end = 0;
	}
	/* +2 so we can add a null entry on the end */
	*words = (char **)realloc(*words,sizeof(char *) * (*word_cnt+2));
	assert(*words);
	(*words)[*word_cnt] = strdup(word);

	++*word_cnt;
	if (end) *end = c;
}




void freeWords(char **words, int word_cnt)
{
	int i;
	for(i=0;i < word_cnt;++i) free(words[i]);
	free(words);
}
