#include "globals.h"

void setState(int st)
{
	char *name[NUM_STATES] =
	{
		"NOTSET","TELOPT","LOGIN","PWD","PIPE"
	};
	if (st == state) assert(0);
	logprintf(getpid(),"Setting state to %s (%d)\n",name[st],st);
	if (state == STATE_TELOPT)
		logprintf(getpid(),"Further telopt codes will be ignored.\n");
	state = st;
}




/*** Parse the path for tilda paths. eg: ~ or ~fred ***/
void parsePath(char **path)
{
	static char *home_dir = NULL;
	struct passwd *pwd;
	char *str;
	char *ptr;
	char *dir;
	char *newpath;
	int slash;

	str = *path;

	/* Only deal with tilda if its the first character */
	if (str[0] != '~') return;

	++str;

	/* Get end of first path section */
	for(ptr=str,slash=0;*ptr;++ptr)
	{
		if (*ptr == '/')
		{
			slash = 1;
			break;
		}
	}
	*ptr = 0;

	/* Can have ~ or ~<user> */
	if (isalpha(*str))
	{
		pwd = getpwnam(str);
		if (!pwd)
		{
			logprintf(0,"ERROR: parsePath(): Cannot get home directory of user \"%s\".\n",str);
			parentExit(-1);
		}
		dir = pwd->pw_dir;
	}
	else
	{
		if (!home_dir)
		{
			pwd = getpwuid(getuid());
			if (!pwd || !pwd->pw_dir)
			{
				logprintf(0,"ERROR: parsePath(): Cannot get home directory for user id %d.\n",getuid());
				parentExit(-1);
			}
			home_dir = strdup(pwd->pw_dir);
		}
		dir = home_dir;
	}
	
	/* Set new path */
	if (slash)
		asprintf(&newpath,"%s/%s",dir,ptr+1);
	else
		newpath = strdup(dir);
	free(*path);
	*path = newpath;
}




void parentExit(int code)
{
	if (code > 0)
		logprintf(parent_pid,"Parent process EXIT on signal %d.\n",code);
	else
	{
		code = -code;
		logprintf(parent_pid,"Parent process EXIT with code %d.\n",code);
	}
	exit(code);
}
