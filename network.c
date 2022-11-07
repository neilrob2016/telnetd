#include "globals.h"

void hexdump(u_char *start, u_char *end, int rx);
void processChar(u_char c);
void processLine();


/*** Create the socket to initially connect to ***/
void createListenSocket()
{
	struct sockaddr_in bind_addr;
	int on;

	if ((listen_sock = socket(AF_INET,SOCK_STREAM,0)) == -1)
	{
		logprintf(0,"ERROR: createListenSocket(): socket(): %s\n",
			strerror(errno));
		exit(1);
	}

	on = 1;
	if (setsockopt(
		listen_sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) == -1)
	{
		logprintf(0,"ERROR: createListenSocket(): setsockopt(SO_REUSEADDR): %s\n",
			strerror(errno));
		exit(1);
	}

	if (iface)
	{
		logprintf(0,">>> Using interface \"%s\", address %s\n",
			iface,inet_ntoa(iface_in_addr.sin_addr));
	}
	else logprintf(0,">>> Using interface INADDR_ANY\n");

	bzero(&bind_addr,sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(port);
	bind_addr.sin_addr.s_addr = iface_in_addr.sin_addr.s_addr;

	if (bind(
		listen_sock,
		(struct sockaddr *)&bind_addr,sizeof(bind_addr)) == -1)
	{
		logprintf(0,"ERROR: createListenSocket(): bind(): %s\n",
			strerror(errno));
		exit(1);
	}

	if (listen(listen_sock,20) == -1)
	{
		logprintf(0,"ERROR: createListenSocket(): listen(): %s\n",
			strerror(errno));
		exit(1);
	}
	logprintf(0,">>> Listening on port %d\n",port);
}




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
		/* Will never return but break keeps compiler happy */
		break;
	case 0:
		logprintf(master_pid,"CONNECTION CLOSED by remote client\n");
		masterExit(0);
	}

	/* end is the next position after the last character */
	end = buff + buffpos + len;
	buff[buffpos+len] = 0;

	if (flags.hexdump) hexdump(buff+buffpos,end,1);

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

	if (flags.echo)
	{
		switch(c)
		{
		case '\r':
		case '\n':
			sockprintf("\r\n");
			break;

		case DELETE_KEY:
			sockprintf("\b \b");
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
			sockprintf(login_prompt);
			return;
		}
		if (loginAllowed((char *)line))
			setUserNameAndPwdState((char *)line);
		break;

	case STATE_PWD:
		/* Unlike username we don't check for a zero length pwd because
		   the username may have been auto filled in but the user wants
		   to use a different one and pressing return on the password 
		   is the easiest way to get back to the login prompt */
		sockprintf("\r\n");
		flags.echo = 1;
		switch(validatePwd((char *)line))
		{
		case -1:
			sockprintf("\r\n%s\r\n\r\n",login_svrerr_msg);
			logprintf(master_pid,"ERROR: processLine(): validatePwd() returned -1 for user \"%s\".\n",username);
			masterExit(0);
			/* Won't get here */
			break;
		case 0:
			checkLoginAttempts();
			sockprintf("%s\r\n",login_incorrect_msg);

			if (login_pause_secs) sleep(login_pause_secs);
			sockprintf(login_prompt);
			setState(STATE_LOGIN);
			break;
		case 1:
			logprintf(master_pid,"User validated as \"%s\".\n",
				username);
			setState(STATE_SHELL);
			runSlave();
			break;
		default:
			assert(0);
		}
		break;
	default:
		/* Shouldn't be in any other states in this function */
		assert(0);
	}
	line[0] = 0;
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
	if (flags.hexdump) hexdump((u_char *)data,(u_char *)data+len,0);
}
