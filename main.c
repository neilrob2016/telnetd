/*****************************************************************************
 NJR-TelnetD

 A simple telnet daemon. Perhaps doesn't do all the telopt negotiation that
 it should. Linux and MacOS only.

 Original version written in December 2018
 *****************************************************************************/

#define MAINFILE
#include "globals.h"

void init();
void parseCmdLine(int argc, char **argv);
void version();
void createListenSocket();
void beDaemon();
void setUpSignals();
void mainloop();
void hupHandler(int sig);
void parentSigHandler(int sig);


/*********************************** INIT ***********************************/

int main(int argc, char **argv)
{
	init();
	parseCmdLine(argc,argv);
	version();
	parseConfigFile();
	createListenSocket();
	if (flags.daemon) beDaemon();
	setUpSignals();
	mainloop();
	return 0;
}



void init()
{
	config_file = CONFIG_FILE;
	port = PORT;
	login_prompt = NULL;
	pwd_prompt = NULL;
	login_incorrect_msg = NULL;
	login_max_attempts_msg = NULL;
	banned_user_msg = NULL;
	login_max_attempts = LOGIN_MAX_ATTEMPTS;
	login_pause_secs = LOGIN_PAUSE_SECS;
	login_timeout_secs = LOGIN_TIMEOUT_SECS;
	telopt_timeout_secs = TELOPT_TIMEOUT_SECS;
	banned_users = NULL;
	banned_users_cnt = 0;
	shell_exec_argv = NULL;
	login_exec_argv = NULL;
	login_exec_argv_cnt = 0;
	log_file_max_fails = LOG_FILE_MAX_FAILS;
	log_file_fail_cnt = 0;
	motd_file = NULL;
	log_file = NULL;
	iface = NULL;
	iface_in_addr.sin_addr.s_addr = INADDR_ANY;
	state = STATE_NOTSET;
	parent_pid = getpid();
	bzero(&flags,sizeof(flags));
}




/*** Guess ***/
void parseCmdLine(int argc, char **argv)
{
	int i;
	char c;

	for(i=1;i < argc;++i)
	{
		if (argv[i][0] != '-' || strlen(argv[i]) != 2) goto USAGE;
		c = argv[i][1];

		if (c == 'v')
		{
			/* Defer it in case we want it written to the log */
			flags.version = 1;
			continue;
		}
		if (++i == argc) goto USAGE;

		switch(c)
		{
		case 'c':
			config_file = argv[i];
			continue;
		case 'f':
			if ((log_file_max_fails = atoi(argv[i])) < 0)
				goto USAGE;
			flags.log_fails_override = 1;
			continue;
		case 'l':
		case 'r':
			log_file = strdup(argv[i]);
			flags.log_file_override = 1;
			if (c == 'r') unlink(log_file);
			continue;
		default:
			goto USAGE;
		}
	}
	if (flags.version)
	{
		version();
		exit(0);
	}
	return;

	USAGE:
	printf("Usage: %s\n"
	       "       -c            : Configuration file. Default = %s\n"
	       "       -l <log file> : Overrides log file in config file.\n"
	       "       -r <log file> : Same as -l except it removes the log file first if it\n"
	       "                       already exists.\n"
	       "       -f <count>    : Maximum number of log file write fails before reverting\n"
	       "                       back to logging to stdout.\n"
	       "       -v            : Print version then exit.\n"
	       "All arguments are optional.\n",argv[0],CONFIG_FILE);
	exit(1);
}




void version()
{
	logprintf(0,"\n*** %s ***\n\n",SVR_NAME);
	logprintf(0,"Version   : %s\n",SVR_VERSION);
	logprintf(0,"Build     : ");
#ifdef __APPLE__
	logprintf(0,"MacOS\n");
#else
	logprintf(0,"Linux/generic\n");
#endif
	logprintf(0,"Build date: %s\n",SVR_BUILD_DATE);
	logprintf(0,"Parent PID: %u\n\n",getpid());
}




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




void beDaemon()
{
	int i;

	/* If parent is init (pid 1) then we're already a daemon so don't
	   bother. Remember on reboot we only exec(), not fork() so parent
	   remains the same */
	if (getppid() == 1) return;

	logprintf(0,"Becoming background daemon...\n");

	switch(fork())
	{
	case -1:
		logprintf(0,"ERROR: beDaemon(): fork(): %s\n",strerror(errno));
		exit(1);
	case 0:
		/* Child continues */
		parent_pid = getpid();
		break;
	default:
		/* Original parent process dies */
		exit(0);
	}

	/* Dissociate in,out,err from TTY */
	for(i=0;i < 2;++i)
	{
		/* Just to be safe */
		if (isatty(i))
		{
			ioctl(i,TIOCNOTTY,NULL);
			close(i);
		}
	}
	setpgrp();
}




void setUpSignals()
{
	/* Not going to bother to reap in the parent process */
	signal(SIGCHLD,SIG_IGN);

	/* SIGHUP causes a re-read of the config file */
	signal(SIGHUP,hupHandler);

	/* Block SIGUSR1 so we can sigwait() on it. Set others to point at
	   handler */
	sigemptyset(&sigmask);
	sigaddset(&sigmask,SIGUSR1);
	sigprocmask(SIG_BLOCK,&sigmask,NULL);

	/* Exit handler */
	signal(SIGINT,parentSigHandler);
	signal(SIGQUIT,parentSigHandler);
	signal(SIGTERM,parentSigHandler);
}



/********************************* RUNTIME **********************************/

/*** Does what it says on the tin ***/
void mainloop()
{
	struct linger lin;
	struct hostent *host;
	struct sockaddr_in ip_addr;
	socklen_t size;
	char *dns;

	logprintf(parent_pid,"*** Started ***\n");

	size = sizeof(ip_addr);
	lin.l_onoff = 1;
	lin.l_linger = 1;

	/* Sit in accept and just fork off a child when it returns */
	while(1)
	{
		if ((sock = accept(
			listen_sock,(struct sockaddr *)&ip_addr,&size)) == -1)
		{
			/* This is fairly terminal , just die */
			logprintf(parent_pid,"ERROR: mainloop(): accept(): %s\n",
				strerror(errno));
			parentExit(-1);
		}

		if (setsockopt(
			sock,
			SOL_SOCKET,SO_LINGER,(char *)&lin,sizeof(lin)) == -1)
		{
			logprintf(parent_pid,"WARNING: mainloop(): setsockopt(SO_LINGER): %s\n",
				strerror(errno));
		}
		if ((host = gethostbyaddr(
			(char *)&(ip_addr.sin_addr.s_addr),
			sizeof(ip_addr.sin_addr.s_addr),
			AF_INET)))
		{
			dns = host->h_name;
		}
		else dns = "<unknown>";

		strcpy(ipaddr,inet_ntoa(ip_addr.sin_addr));
		logprintf(parent_pid,"CONNECTION from %s (%s)\n",ipaddr,dns);

		/* Don't want children inheriting this handler */
		signal(SIGHUP,SIG_IGN);

		switch(fork())
		{
		case -1:
			logprintf(parent_pid,"ERROR: mainloop(): fork(): %s\n",
				strerror(errno));
			break;
		case 0:
			close(listen_sock);
			runMaster();
			break;
		default:
			/* Reinstate handler for parent */
			signal(SIGHUP,hupHandler);
			break;
		}
		close(sock);
	}
}




void hupHandler(int sig)
{
	logprintf(parent_pid,">>> SIGNAL %d (SIGHUP), re-reading config...\n",SIGHUP);
	bzero(&flags,sizeof(flags));
	flags.sighup = 1;
	parseConfigFile();
}




void parentSigHandler(int sig)
{
	logprintf(parent_pid,">>> SIGNAL %d, exiting...\n",sig);
	close(listen_sock);
	parentExit(sig);
}
