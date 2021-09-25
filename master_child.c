/*****************************************************************************
 This child process is spawned off from the parent after an accept() call and
 it is the PTY master (ie network) side of the link. It received data from
 the socket and writes it to the PTY. Similarly it reads data from the PTY and
 sends it down the socket.
 *****************************************************************************/

#include "globals.h"

static char **user_list;
static int user_cnt;

void sendMOTD();
int  getUserCount(int unique);
void addUser(char *username);
void freeUsers();
void childSigHandler(int sig);
void readPTYMaster();


/*** Child process executes from here ***/
void childMain()
{
	struct timeval tvs;
	struct timeval *tvp;
	int wait_cnt;
	fd_set mask;

	ptym = -1;
	term_height = 25;
	term_width = 80;
	line_buffpos = 0;
	attempts = 0;
	prev_c = 0;
	got_term_type = 0;
	child_pid = getpid();
	state = (shell ? STATE_LOGIN : STATE_SHELL);

	logprintf(child_pid,"MASTER CHILD STARTED\n");

	/* Leave parents process group so ^C or ^\ on the parent process 
	   doesn't kill the children. Need setpgrp(0,0) for BSD. Don't do
	   setsid() here because we want to printf messages to terminal. */
	setpgrp();

	if (!openPTYMaster())
	{
		sockprintf("ERROR: Open PTY master failed.\n");
		childExit(1);
	}
	logprintf(child_pid,"PTY = %s\n",getPTYName());

	signal(SIGINT,childSigHandler);
	signal(SIGQUIT,childSigHandler);
	signal(SIGTERM,childSigHandler);

	if (motd_file) sendMOTD();

	sendInitialTelopt();

	if (state == STATE_LOGIN)
	{
		wait_cnt = 0;
		writeSockStr(login_prompt);
	}
	else wait_cnt = 5; /* Telopt replies are unlikely to be in same pkt */

	/* Sit in a loop reading from the socket and pty master */
	while(1)
	{
		FD_ZERO(&mask);
		FD_SET(sock,&mask);

		if (ptym != -1) FD_SET(ptym,&mask);

		/* Need to reset each time */
		if (login_timeout_secs && state != STATE_SHELL)
		{
			tvs.tv_sec = login_timeout_secs;
			tvs.tv_usec = 0;
			tvp = &tvs;
		}
		else if (wait_cnt)
		{
			/* If we're going to exec /bin/login directly then 
			   wait a short period for the client to send the
			   terminal type as this can't be passed as an ioctl()
			   from master to slave pty */
			if (got_term_type || !--wait_cnt)
			{
				execShell();
				tvp = NULL;
				wait_cnt = 0;
			}
			else
			{
				/* Need a timeout so we don't sit waiting
				   forever for a telopt */
				tvs.tv_sec = 0;
				tvs.tv_usec = 200000;
				tvp = &tvs;
			}
		}
		else tvp = NULL;

		switch(select(FD_SETSIZE,&mask,0,0,tvp))
		{
		case -1:
			logprintf(child_pid,"ERROR: select(): %s\n",
				strerror(errno));
			childExit(1);
			break;
		case 0:
			if (wait_cnt) continue;
			writeSockStr("\r\n\r\nTimeout.\r\n\r\n");
			childExit(0);
		}

		if (FD_ISSET(sock,&mask)) readSock();
		if (ptym != -1 && FD_ISSET(ptym,&mask)) readPTYMaster();
	}
}




/*** Send the message of the day file translating any codes as we go ***/
void sendMOTD()
{
	FILE *fp;
	struct tm *tms;
	struct utsname uts;	
	time_t now;
	char out[BUFFSIZE+1];
	char str[100];
	char c;
	int len;
	int esc;
	int i;

	if (!(fp = fopen(motd_file,"r")))
	{
		logprintf(child_pid,"ERROR: fopen(\"%s\"): %s\n",
			motd_file,strerror(errno));
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
				writeSockStr("0");
				break;
			case 'd':
				strftime(str,sizeof(str),"%F",tms);
				writeSockStr(str);
				break;
			case 'l':
				writeSockStr(getPTYName());
				break;
			case 'm':
				writeSockStr(uts.machine);
				break;
			case 'n':
				writeSockStr(uts.nodename);
				break;
			case 'r':
				writeSockStr(uts.release);
				break;
			case 's':
				writeSockStr(uts.sysname);
				break;
			case 't':
				strftime(str,sizeof(str),"%T",tms);
				writeSockStr(str);
				break;
			case 'u':
				sprintf(str,"%d",getUserCount(1));
				writeSockStr(str);
				break;
			case 'U':
				sprintf(str,"%d",getUserCount(0));
				writeSockStr(str);
				break;
			case 'v':
				writeSockStr(uts.version);
				break;
			case 'x':
				writeSockStr(SVR_NAME);
				break;
			case 'y':
				writeSockStr(SVR_VERSION);
				break;
			case 'z':
				writeSockStr(SVR_BUILD_DATE);
				break;
			default:	
				writeSockStr("??");
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
	int cnt;

#ifdef __APPLE__
	struct utmpx *ux;

	user_list = NULL;
	user_cnt = 0;
	for(cnt=0;(ux = getutxent());)
	{
		if (ux->ut_type == USER_PROCESS)
		{
			if (unique)
				addUser(ux->ut_user);
			else
				++cnt;
		}
	}
	endutxent();
#else
	struct utmp u;
	int fd;

	user_list = NULL;
	user_cnt = 0;
	if ((fd = open("/var/run/utmp",O_RDONLY)) == -1 &&
	    (fd = open("/var/log/utmp",O_RDONLY)) == -1 &&
	    (fd = open("/var/adm/utmp",O_RDONLY)) == -1 &&
	    (fd = open("/etc/utmp",O_RDONLY)) == -1)
	{
		logprintf(child_pid,"ERROR: Utmp: open(): %s\n",strerror(errno));
		return 0;
	}
	for(cnt=0;read(fd,(char *)&u,sizeof(u));)
	{
		if (u.ut_type == USER_PROCESS)
		{
			if (unique)
				addUser(u.ut_user);
			else
				++cnt;
		}
	}
	close(fd);
#endif
	if (unique)
	{
		cnt = user_cnt;
		freeUsers();
	}
	return cnt;
}




/*** Add a username to the unique list if not there ***/
void addUser(char *username)
{
	int i;
	for(i=0;i < user_cnt;++i)
		if (!strcmp(user_list[i],username)) return;
	user_list = (char **)realloc(user_list,(user_cnt + 1) * sizeof(char **));
	if (user_list)
	{
		user_list[user_cnt] = strdup(username);
		if (user_list[user_cnt]) ++user_cnt;
	}
}




void freeUsers()
{
	int i;
	for(i=0;i < user_cnt;++i) free(user_list[i]);
	free(user_list);
}




/*** Read from the pty master ***/
void readPTYMaster()
{
	int len;

	switch((len = read(ptym,ptybuff,BUFFSIZE)))
	{
	case -1:
		logprintf(child_pid,"ERROR: read(ptym): %s\n",strerror(errno));
		childExit(1);
	case 0:
		/* Read nothing, slave has exited */
		logprintf(child_pid,"PTY %s closed\n",getPTYName());
		childExit(0);
	default:
		writeSock(ptybuff,len);
	}
}




/*** Send window size down to slave pty ***/
void sendWinSize()
{
	struct winsize ws;
	char str[10];

	if (ptym == -1) return;

	bzero(&ws,sizeof(ws));
	ws.ws_row = term_height;
	ws.ws_col = term_width;

	ioctl(ptym,TIOCSWINSZ,&ws);

	/* Belt and braces */
	snprintf(str,sizeof(str),"%u",term_width);
	setenv("COLUMNS",str,1);
	snprintf(str,sizeof(str),"%u",term_height);
	setenv("LINES",str,1);
}




void childSigHandler(int sig)
{
	logprintf(child_pid,"SIGNAL %d, exiting...\n",sig);
	childExit(sig);
}




void childExit(int code)
{
	logprintf(child_pid,"EXIT with code %d\n",code);
	close(ptym);
	close(sock);
	exit(code);
}
