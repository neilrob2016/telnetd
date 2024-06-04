#include "globals.h"

static int wildMatch(const char *str, const char *pat);

void addToIPList(char *addrstr)
{
	char *ptr;
	char *end;
	char prev_c;
	char c;
	int cnt;

	if ((int)inet_addr(addrstr) == -1)
	{
		end = addrstr + strlen(addrstr) - 1;
		prev_c = 0;

		/* Check for invalid characters and some other errors. This 
		   isn't a fullproof validator */
		for(ptr=addrstr,cnt=0;*ptr;++ptr)
		{
			c = tolower(*ptr);
			switch(c)
			{
			case '*':
			case '?':
				break;
			case '.':
				if (prev_c == '.' ||
				    ptr == addrstr ||
				    ptr == end || ++cnt > 3) goto INVALID;
				break;
			default:
				if ((c < 'a' || c > 'z') && 
				    (c < '0' || c > '9') && c != '-')
				{
					goto INVALID;
				}
			}
			prev_c = c;
		}
	}
	
	/* There won't be many so don't need to preallocate for efficiency */
	iplist = (char **)realloc(iplist,sizeof(char *) * ++iplist_cnt);
	assert(iplist);
	iplist[iplist_cnt-1] = strdup(addrstr);
	return;

	INVALID:
	logprintf(0,"ERROR: Invalid IP/DNS address \"%s\".\n",addrstr);
	parentExit(-1);
}



int authorisedIP(char *addrstr)
{
	int i;

	/* If no list then no restrictions */
	if (!iplist_cnt) return 1;

	/* Find match in list */
	for(i=0;i < iplist_cnt;++i)
	{
		if (wildMatch(addrstr,iplist[i]))
			return (iplist_type == IP_WHITELIST ? 1 : 0);
	}

	/* Not found */
	return (iplist_type == IP_WHITELIST ? 0 : 1);
}




/*** Returns 1 if the string matches the pattern, else 0. Supports wildcard 
     patterns containing '*' and '?'. Case insensitive. ***/
int wildMatch(const char *str, const char *pat)
{
	char *s;
	char *s2;
	char *p;

	for(s=(char *)str,p=(char *)pat;*s && *p;++s,++p)
	{
		switch(*p)
		{
		case '?':
			continue;

		case '*':
			if (!*(p+1)) return 1;

			for(s2=s;*s2;++s2) if (wildMatch(s2,p+1)) return 1;
			return 0;
		}
		if (toupper(*s) != toupper(*p)) return 0;
	}

	/* Could have '*' leftover in the pattern which can match nothing.
	   eg: "abc*" should match "abc" and "*" should match "" */
	if (!*s)
	{
		/* Could have multiple *'s on end which should all match "" */
		for(;*p && *p == '*';++p);
		if (!*p) return 1;
	}
	return 0;
}
