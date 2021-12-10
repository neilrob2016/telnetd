#include "globals.h"

void hexdump(u_char *start, u_char *end, int rx);
void processChar(u_char c);
void processLine();
int  checkLogin(char *password);


/*** Read from the socket and call processChar() function ***/
void readSock()
{
	int len;
	u_char *p1;
	u_char *p2;
	u_char *end;

	if (buffpos >= BUFFSIZE)
	{
		sockprintf("ERROR: Buffer overrun.\n");
		logprintf(master_pid,"ERROR: readSock(): Buffer overrun.");
		masterExit(1);
	}
	switch((len = read(sock,buff+buffpos,BUFFSIZE-buffpos)))
	{
	case -1:
		logprintf(master_pid,"ERROR: readSock(): %s\n",strerror(errno));
		masterExit(1);

	case 0:
		logprintf(master_pid,"CONNECTION CLOSED by remote client\n");
		masterExit(0);
	}

	/* end is the next position after the last character */
	end = buff + buffpos + len;
	buff[buffpos+len] = 0;

	if (flags & FLAG_HEXDUMP) hexdump(buff+buffpos,end,1);

	/*** Loop through whats currently in the buffer ***/
	for(p1=buff;p1 < end;++p1)
	{
		/* If not a telopt process or we're not longer examining
		   telopt data then treat as a normal character */
		if (*p1 != TELNET_IAC)
		{
			processChar(*p1);
			continue;
		}

		/* If IAC at end put it at start of the buffer and return */
		if (p1 == end - 1)
		{
			buff[0] = TELNET_IAC;
			buffpos = 1;
			return;
		}

		/* If IAC twinned then the client wants to print char 255 */
		if (*(p1 + 1) == TELNET_IAC)
		{
			processChar(255);
			p1++;  /* Skip to next IAC */
			continue;
		}

		/* Parse telopt code */
		if (!(p2 = parseTelopt(p1,end)))
		{
			/* If it returned null then end of the buffer was hit
			   before complete telopt */
			buffpos = (int)(end - p1);
			memmove(buff,p1,buffpos);
			return;
		}
		p1 = p2;
	}
}




/*** Hexdump to the log file ***/
void hexdump(u_char *start, u_char *end, int rx)
{
	char str[HEXDUMP_CHARS * 10];
	char add[4];
	u_char *linestart;
	u_char *ptr;
	u_char c;
	int i;

	for(ptr=linestart=start;ptr < end;linestart=ptr)
	{
		strcpy(str,rx ? "RX: | " : "TX: | ");

		/* Do hex values */
		for(i=0;i < HEXDUMP_CHARS;++i)
		{
			if (ptr < end)
			{
				sprintf(add,"%02X ",*ptr);
				strcat(str,add);
				++ptr;
			}
			else strcat(str,"   ");
		}
		strcat(str,"| ");

		/* Do characters */
		for(i=0,ptr=linestart;i < HEXDUMP_CHARS;++i)
		{
			if (ptr < end)
			{
				c = *ptr;
				add[0] = (c > 31 && c < 128) ? (char)c : '.';
				add[1] = 0;
				strcat(str,add);
				++ptr;
			}
			else strcat(str," ");
		}
		strcat(str,"\n");
		logprintf(master_pid,str);
	}
}




/*** Do something with the non telopt character we've just received ***/
void processChar(u_char c)
{
	/* Telnet passes \r\0 for newlines, ignore the \0 */
	if (prev_c == '\r' && !c)
	{
		prev_c = c;
		return;
	}

	switch(state)
	{
	case STATE_SHELL:
		/* Just write through to pty, no processing. */
		write(ptym,&c,1);
		prev_c = c;
		return;
	case STATE_TELOPT:
		/* Ignore any user input in this state */
		return;
	default:
		break;
	}
	prev_c = c;

	if (flags & FLAG_ECHO)
	{
		switch(c)
		{
		case '\r':
		case '\n':
			writeSockStr("\r\n");
			break;

		case DELETE_KEY:
			writeSockStr("\b \b");
			break;

		default:
			writeSock((char *)&c,1);
		}
	}

	switch(c)
	{
	case '\r':
	case '\n':
		processLine();
		return;

	case DELETE_KEY:
		if (line_buffpos) line_buffpos--;
		return;
	}

	line[line_buffpos++] = c;
	if (line_buffpos == BUFFSIZE) processLine();
}




/*** Do something with the line in the buffer ***/
void processLine()
{
	line[line_buffpos] = 0;
	line_buffpos = 0;

	switch(state)
	{
	case STATE_LOGIN:
		if (!line[0])
		{
			writeSockStr(login_prompt);
			return;
		}
		if (loginAllowed((char *)line))
			setUserNameAndPwdState((char *)line);
		break;

	case STATE_PWD:
		flags |= FLAG_ECHO;
		writeSockStr("\r\n");
		if (!checkLogin((char *)line))
		{
			writeSockStr("Login incorrect.\r\n");
			checkLoginAttempts();

			if (login_pause_secs) sleep(login_pause_secs);
			writeSockStr(login_prompt);
			setState(STATE_LOGIN);
			break;
		}
		logprintf(master_pid,"User logged in as \"%s\".\n",username);
		setState(STATE_SHELL);
		runSlave();
		break;

	default:
		/* Shouldn't be in any other states in this function */
		assert(0);
	}
	line[0] = 0;
}




/*** None of this works on MacOS which is why the shell options are ifndef'd 
     out in parseCmdLine() ***/
int checkLogin(char *password)
{
#ifdef __APPLE__
	return 0;
#else
	struct spwd *spwd;
	char *pwd;
	char *salt;
	char *hash;
	char *cry;
	int len;

	/* Check user exists */
	if (!(userinfo = getpwnam(username))) return 0;

	/* If no password then get info from shadow password file */
	if (!strcmp(userinfo->pw_passwd,"x"))
	{
		if (!(spwd = getspnam(userinfo->pw_name)))
		{
			sockprintf("ERROR: checkLogin(): getspnam(): %s\n",strerror(errno));
			return 0;
		}
		pwd = spwd->sp_pwdp;
	}
	else pwd = userinfo->pw_passwd;

	/* If we have a '.' in the hash thats the delimiter between the salt
	   and the password hash, else look for the last '$' else just use the 
	   1st 2 characters for the salt */
	if ((hash = strchr(pwd,'.')) ||
	    (hash = strrchr(pwd,'$')))
	{
		len = (int)(hash - pwd);
		asprintf(&salt,"%.*s",len,pwd);
		++hash;
	}
	else
	{
		asprintf(&salt,"%.2s",pwd);
		hash = pwd + 2;
	}
	if (!(cry = crypt(password,salt)))
		logprintf(master_pid,"ERROR: checkLogin(): crypt() returned NULL");
	free(salt);
	return (cry ? !strcmp(cry,pwd) : 0);
#endif
}




/*** Write down the socket ***/
void writeSock(char *data, int len)
{
	int bytes;
	int i;
	int l;

	for(bytes=0;bytes < len;)
	{
		/* Retry 3 times */
		for(i=0;i < 3;++i)
		{
			if (i) logprintf(master_pid,"Write retry #%d\n",i);
			if ((l = write(sock,data + bytes,len - bytes)) == -1)
			{
				if (errno == EINTR) 
				{
					logprintf(master_pid,"ERROR: writeSock(): write(): Interrupted");
					continue;
				}
				logprintf(master_pid,"ERROR: writeSock(): write(): %s\n",strerror(errno));
			}
			else break;
		}
		if (i == 3)
		{
			logprintf(master_pid,"ERROR: writeSock(): Failed to write data.\n");
			return;
		}
		bytes += l;
	}
	if (flags & FLAG_HEXDUMP) hexdump((u_char *)data,(u_char *)data+len,0);
}




void writeSockStr(char *str)
{
	writeSock(str,strlen(str));
}
