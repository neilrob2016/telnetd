#include "globals.h"

static char **user_list;
static int unique_cnt;

static int getUserCount(int unique);
static void addUserToUniqueList(char *username);


/*** Send the message of the day file translating any codes as we go ***/
void sendMOTD(char *file)
{
	FILE *fp;
	struct tm *tms;
	struct utsname uts;	
	time_t now;
	u_char out[BUFFSIZE+1];
	char str[100];
	char c;
	int len;
	int esc;
	int i;

	if (!(fp = fopen(file,"r")))
	{
		logprintf(master_pid,"ERROR: sendMOTD(): fopen(\"%s\"): %s\n",
			file,strerror(errno));
		return;
	}

	/* Get data for escape codes. Might not be used but keeps code tidier */
	time(&now);
	tms = localtime(&now);
	uname(&uts);

	/* Read in the file a character at a time in order to find the escape
	   codes easily */
	for(esc=len=0;(i=getc(fp)) != EOF;)
	{
		c = (char)i;
		/* Convert \n to \r\n */
		if (c == '\n')
		{
			writeSock(out,len);
			len = 0;
			out[len++] = '\r';
			out[len++] = '\n';
			continue;
		}

		if (c == '\\')
		{
			if (esc)
			{
				out[len++] = '\\';
				esc = 0;
			}
			else esc = 1;
		}
		else if (esc)
		{
			writeSock(out,len);
			len = 0;

			/* Same escape options as /etc/issue except for 'x', 
			   'y' and 'z' which are my own */
			switch(c)
			{
			case 'b':
				/* Can't get baud rate for a pty so just 
				   return zero */
				sockprintf("0");
				break;
			case 'd':
				strftime(str,sizeof(str),"%F",tms);
				sockprintf(str);
				break;
			case 'l':
				sockprintf(getPTYName());
				break;
			case 'm':
				sockprintf(uts.machine);
				break;
			case 'n':
				sockprintf(uts.nodename);
				break;
			case 'r':
				sockprintf(uts.release);
				break;
			case 's':
				sockprintf(uts.sysname);
				break;
			case 't':
				strftime(str,sizeof(str),"%T",tms);
				sockprintf(str);
				break;
			case 'u':
				sprintf(str,"%d",getUserCount(1));
				sockprintf(str);
				break;
			case 'U':
				sprintf(str,"%d",getUserCount(0));
				sockprintf(str);
				break;
			case 'v':
				sockprintf(uts.version);
				break;
			case 'x':
				sockprintf(SVR_NAME);
				break;
			case 'y':
				sockprintf(SVR_VERSION);
				break;
			case 'z':
				sockprintf(BUILD_DATE);
				break;
			default:	
				sockprintf("??");
			}
			esc = 0;
		}
		else out[len++] = c;
		
		if (len == BUFFSIZE)
		{
			writeSock(out,len);
			len = 0;
		}
	}
	if (esc) out[len++] = '\\';
	if (len) writeSock(out,len);
	fclose(fp);
}




/*** Get the number of users/logins on the system for MOTD ***/
int getUserCount(int unique)
{
	struct utmpx *ux;
	int cnt;
	int i;

	user_list = NULL;
	unique_cnt = 0;

	setutxent();
	for(cnt=0;(ux = getutxent());)
	{
		if (ux->ut_type == USER_PROCESS)
		{
			if (unique)
				addUserToUniqueList(ux->ut_user);
			else
				++cnt;
		}
	}
	endutxent();

	if (unique)
	{
		/* Free the list */
		for(i=0;i < unique_cnt;++i) free(user_list[i]);
		free(user_list);
		return unique_cnt;
	}
	return cnt;
}




/*** Add a username to the unique list if not there ***/
void addUserToUniqueList(char *username)
{       
	int i;
	for(i=0;i < unique_cnt;++i) if (!strcmp(user_list[i],username)) return;
	
	user_list = (char **)realloc(user_list,(unique_cnt + 1) * sizeof(char **));     
	assert(user_list);
	
	user_list[unique_cnt] = strdup(username);
	assert(user_list[unique_cnt]);
	
	++unique_cnt;
}      
