/*****************************************************************************
 This child process is spawned off from the parent after an accept() call and
 it is the PTY master (ie network) side of the link. It received data from
 the socket and writes it to the PTY. Similarly it reads data from the PTY and
 sends it down the socket.
 *****************************************************************************/

#include "globals.h"

time_t telneg_start;

static void processStateTelopt(void);
static void readPTYMaster(void);
static void masterSigHandler(int sig);


/*** Child master process executes from here ***/
void runMaster(struct sockaddr_in *ip_addr)
{
	struct timeval tvs;
	struct timeval *tvp;
	struct hostent *host;
	fd_set mask;

	ptym = -1;
	term_height = 25;
	term_width = 80;
	line_buffpos = 0;
	attempts = 0;
	prev_rx_c = 0;
	telopt_username = NULL;
	telneg_start = time(0);
	master_pid = getpid();
	slave_pid = -1;
	dnsaddr = NULL;

	/* A host lookup can block for a while so we do it in this process 
	   instead of in the main loop in the parent process */
	if (flags.dns_lookup && (host = gethostbyaddr(
		(char *)&(ip_addr->sin_addr.s_addr),
		sizeof(ip_addr->sin_addr.s_addr),AF_INET)))
	{
		dnsaddr = strdup(host->h_name);
	}

	logprintf(master_pid,"STARTED: Master process, ppid = %d, DNS name = %s\n",
		parent_pid,dnsaddr ? dnsaddr : "<not set>");

	if (dnsaddr && !authorisedIP(dnsaddr))
	{
		logprintf(master_pid,"CONNECTION REFUSED: Banned DNS address.\n");
		if (banned_ip_msg) sockprintf("%s\r\n",banned_ip_msg);
		masterExit(1);
	}

	setState(STATE_TELOPT);

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

	if (pre_motd_file) sendMOTD(pre_motd_file);

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




/*** Telnet negotiations have finished or failed so do some actions before
     switching to a new state */
void processStateTelopt(void)
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




void checkLoginAttempts(void)
{
	if (++attempts >= login_max_attempts)
	{
		sockprintf("\r\n%s\r\n\r\n",login_max_attempts_msg);
		/* login_max_attempts could have been changed in pwd file so
		   print it out */
		logprintf(master_pid,"Maximum login attempts (%d) reached.\n",
			login_max_attempts);
		masterExit(0);
	}
}




/*** Read from the pty master ***/
void readPTYMaster(void)
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
		break;
	default:
		writeSock((u_char *)ptybuff,len);
	}
}




void masterSigHandler(int sig)
{
	logprintf(master_pid,"EXIT: Master process on signal %d.\n",sig);
	masterExit(sig);
}




void masterExit(int code)
{
	int status;

	if (ptym != -1) close(ptym);
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
			logprintf(master_pid,"EXIT: Slave process %d with code %d.\n",
				slave_pid,WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status))
		{
			logprintf(master_pid,"EXIT: Slave process %d on signal %d%s\n",
				slave_pid,
				WTERMSIG(status),
				WCOREDUMP(status) ? " (core dumped)." : ".");
		}
		else logprintf(master_pid,"EXIT: Slave process %d, state unknown.\n",slave_pid);
	}
	else logprintf(master_pid,"No slave process to reap.\n");

	logprintf(master_pid,"EXIT: Master process with code %d.\n",code);
	exit(code);
}
