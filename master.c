/*****************************************************************************
 This child process is spawned off from the parent after an accept() call and
 it is the PTY master (ie network) side of the link. It received data from
 the socket and writes it to the PTY. Similarly it reads data from the PTY and
 sends it down the socket.
 *****************************************************************************/

#include "globals.h"

char **user_list;
int unique_cnt;
time_t telneg_start;

void sendMOTD();
int  getUserCount(int unique);
void addUserToUniqueList(char *username);
void processStateTelopt();
void readPTYMaster();
void masterSigHandler(int sig);


/*** Child master process executes from here ***/
void runMaster()
{
	struct timeval tvs;
	struct timeval *tvp;
	fd_set mask;

	ptym = -1;
	term_height = 25;
	term_width = 80;
	line_buffpos = 0;
	attempts = 0;
	prev_c = 0;
	telopt_username = NULL;
	telneg_start = time(0);
	master_pid = getpid();
	slave_pid = -1;

	setState(STATE_TELOPT);

	logprintf(master_pid,"Master process STARTED.\n");

	/* Leave parents process group so ^C or ^\ on the parent process 
	   doesn't kill the children. Need setpgrp(0,0) for BSD. Don't do
	   setsid() here because we want to printf messages to terminal. */
	setpgrp();

	if (!openPTYMaster()) masterExit(1);

	logprintf(master_pid,"PTY = %s\n",getPTYName());

	signal(SIGCHLD,SIG_DFL);  /* Want to reap zombies */
	signal(SIGINT,masterSigHandler);
	signal(SIGQUIT,masterSigHandler);
	signal(SIGTERM,masterSigHandler);

	if (motd_file) sendMOTD();

	sendInitialTelopt();

	/* Sit in a loop reading from the socket and pty master */
	while(1)
	{
		FD_ZERO(&mask);
		FD_SET(sock,&mask);

		if (ptym != -1) FD_SET(ptym,&mask);
		tvp = NULL;

		switch(state)
		{
		case STATE_TELOPT:
			/* If we've got the telnet info we want or we've timed
			   out then change the state */
			if (time(0) - telneg_start >= telopt_timeout_secs)
			{
				logprintf(master_pid,"WARNING: Telopt negotiation timeout.\n");
				processStateTelopt();
				continue;
			}
			else if (flags.rx_ttype && flags.rx_env)
			{
				processStateTelopt();
				continue;
			}
			tvs.tv_sec = 1;
			tvs.tv_usec = 0;
			tvp = &tvs;
			break;

		case STATE_LOGIN:
		case STATE_PWD:
			if (login_timeout_secs)
			{
				tvs.tv_sec = login_timeout_secs;
				tvs.tv_usec = 0;
				tvp = &tvs;
			}
			else tvp = NULL;
			break;

		case STATE_PIPE:
			/* Do nothing. We're just a pipe from TCP to the shell 
			   process and back now */
			break;

		default:
			assert(0);
		}

		switch(select(FD_SETSIZE,&mask,0,0,tvp))
		{
		case -1:
			logprintf(master_pid,"ERROR: runMaster(): select(): %s\n",
				strerror(errno));
			masterExit(1);
			break;
		case 0:
			if (state == STATE_LOGIN || state == STATE_PWD)
			{
				sockprintf("\r\n\r\n%s\r\n\r\n",login_timeout_msg);
				masterExit(0);
			}
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
		logprintf(master_pid,"ERROR: sendMOTD(): fopen(\"%s\"): %s\n",
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
	int cnt;
	int i;
#ifdef __APPLE__
	struct utmpx *ux;

	user_list = NULL;
	unique_cnt = 0;
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
#else
	struct utmp u;
	int fd;

	user_list = NULL;
	unique_cnt = 0;
	if ((fd = open("/var/run/utmp",O_RDONLY)) == -1 &&
	    (fd = open("/var/log/utmp",O_RDONLY)) == -1 &&
	    (fd = open("/var/adm/utmp",O_RDONLY)) == -1 &&
	    (fd = open("/etc/utmp",O_RDONLY)) == -1)
	{
		logprintf(master_pid,"ERROR: getUserCount(): open(): %s\n",strerror(errno));
		return 0;
	}
	for(cnt=0;read(fd,(char *)&u,sizeof(u));)
	{
		if (u.ut_type == USER_PROCESS)
		{
			if (unique)
				addUserToUniqueList(u.ut_user);
			else
				++cnt;
		}
	}
	close(fd);
#endif
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
	for(i=0;i < unique_cnt;++i)
		if (!strcmp(user_list[i],username)) return;

	user_list = (char **)realloc(user_list,(unique_cnt + 1) * sizeof(char **));
	assert(user_list);

	user_list[unique_cnt] = strdup(username);
	assert(user_list[unique_cnt]);

	++unique_cnt;
}




/*** Telnet negotiations have finished or failed so do some actions before
     switching to a new state */
void processStateTelopt()
{
	if (telopt_username)
	{
		logprintf(master_pid,"Auto setting username to \"%s\".\n",
			telopt_username);
	}
	else logprintf(master_pid,"Client didn't send username.\n");

	/* If we don't have a shell program set then we pass any user input
	   through to the login program */
	if (!shell_exec_argv)
	{
		setState(STATE_PIPE);
		runSlave();
		return;
	}

	/* Send our own login prompt */
	sockprintf(login_prompt);

	/* If we got the username from the client then jump to password input */
	if (telopt_username)
	{
		sockprintf("%s\r\n",telopt_username);

	    	if (loginAllowed(telopt_username))
			setUserNameAndPwdState(telopt_username);
		else
			setState(STATE_LOGIN);

		free(telopt_username);
	}
	else setState(STATE_LOGIN);
}




void setUserNameAndPwdState(char *uname)
{
	strncpy(username,uname,sizeof(username));
	flags.echo = 0;
	sockprintf(pwd_prompt);
	setState(STATE_PWD);
}




int loginAllowed(char *uname)
{
	int i;
	for(i=0;i < banned_users_cnt;++i)
	{
		if (!strcmp(banned_users[i],uname)) 
		{
			checkLoginAttempts();
			sockprintf("%s\r\n%s",banned_user_msg,login_prompt);
			logprintf(master_pid,"WARNING: Attempted login of banned user \"%s\"\n",uname);
			return 0;
		}
	}
	return 1;
}




void checkLoginAttempts()
{
	if (++attempts >= login_max_attempts)
	{
		sockprintf("\r\n%s\r\n\r\n",login_max_attempts_msg);
		logprintf(master_pid,"Maximum login attempts reached.\n");
		masterExit(0);
	}
}




/*** Read from the pty master ***/
void readPTYMaster()
{
	int len;

	switch((len = read(ptym,ptybuff,BUFFSIZE)))
	{
	case -1:
		/* Linux returns I/O error when slave process exits first. 
		   Ignore this, just print others */
		if (errno != EIO)
		{
			logprintf(master_pid,"ERROR: readPTYMaster(): read(): %s\n",
				strerror(errno));
		}
		/* Fall through */
	case 0:
		/* Read nothing, slave has exited */
		logprintf(master_pid,"PTY %s closed.\n",getPTYName());
		masterExit(0);
	default:
		writeSock(ptybuff,len);
	}
}




void masterSigHandler(int sig)
{
	logprintf(master_pid,"Master process EXIT on signal %d.\n",sig);
	masterExit(sig);
}




void masterExit(int code)
{
	int status;

	close(ptym);
	close(sock);

	if (slave_pid != -1)
	{
		/* Reap slave process */
		if (waitpid(slave_pid,&status,WNOHANG) == -1)
		{
			logprintf(master_pid,
				"ERROR: masterExit(): waitpid(): Can't reap slave process %d: %s.\n",
				slave_pid,strerror(errno));
		}
		else if (WIFEXITED(status))
		{
			logprintf(master_pid,"Slave process %d EXITED with code %d.\n",
				slave_pid,WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status))
		{
			logprintf(master_pid,"Slave process %d EXITED on signal %d%s\n",
				slave_pid,
				WTERMSIG(status),
				WCOREDUMP(status) ? " (core dumped)." : ".");
		}
		else logprintf(master_pid,"Slave process %d EXIT state unknown.\n",slave_pid);
	}
	else logprintf(master_pid,"No slave process to reap.\n");

	logprintf(master_pid,"Master process EXIT with code %d.\n",code);
	exit(code);
}
