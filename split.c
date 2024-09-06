#include "globals.h"


/*** Split a space seperated string into individual words. Takes account of 
     quotes. ***/
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




void freeWordArray(char **words, int word_cnt)
{
	int i;
	for(i=0;i < word_cnt;++i) free(words[i]);
	free(words);
}




/***
 Split a line from the telnetd password file. Each line has the format:

 #<comment>
 or
 <username>:<encrypted password>:<max attempts>:<reserved>[:<exec line>]

 The fields don't need to be alloced as "line" stays in scope while the
 fields are parsed in validate.c
***/
char *splitPwdLine(char *line, char *map_end, char **field)
{
	char *p1;
	char *p2;
	char c;
	int i;

	for(i=0;i < NUM_PWD_FIELDS;++i) field[i] = NULL;

	/* Assumes line is at start of a line */
	for(i=0,c=0,p1=line;i < NUM_PWD_FIELDS && p1 < map_end && c != '\n';++i)
	{
		if (*p1 == '#' || *p1 == '\n') break;

		/* Find colon */
		for(p2=p1;p2 < map_end && *p2 != ':' && *p2 != '\n';++p2);
		c = *p2;
		*p2 = 0;
		field[i] = p1;
		p1 = p2 + 1;
	}

	if (p1 == map_end || c == '\n') return p1;
	
	/* Find end of line when more fields than expected */
	for(;p1 < map_end && *p1 != '\n';++p1);
	return p1 + 1;
}
