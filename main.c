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
void printParams();
void createListenSocket();
void mainloop();
void beDaemon();
void setUpSignals();
void parentSigHandler(int sig);


/*** START ***/
int main(int argc, char **argv)
{
	init();
	parseCmdLine(argc,argv);
	version();
	parseConfigFile();
	printParams();
	createListenSocket();
	if (flags & FLAG_DAEMON) beDaemon();
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
	login_max_attempts = LOGIN_MAX_ATTEMPTS;
	login_pause_secs = LOGIN_PAUSE_SECS;
	login_timeout_secs = LOGIN_TIMEOUT_SECS;
	telopt_timeout_secs = LOGIN_TIMEOUT_SECS;
	banned_users = NULL;
	banned_users_cnt = 0;
	shell_exec_argv = NULL;
	login_exec_argv = NULL;
	login_exec_argv_cnt = 0;
	motd_file = NULL;
	log_file = NULL;
	flags = 0;
	iface = NULL;
	iface_in_addr.sin_addr.s_addr = INADDR_ANY;
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

		switch(c)
		{
		case 'c':
			if (++i == argc) goto USAGE;
			config_file = argv[i];
			continue;
		case 'v':
			version();
			exit(0);
		default:
			goto USAGE;
		}
	}
	return;

	USAGE:
	printf("Usage: %s\n"
	       "       -c  : Configuration file. Default = %s\n"
	       "       -v  : Print version then exit.\n",argv[0],CONFIG_FILE);
	exit(1);
}




void version()
{
	printf("\n*** %s ***\n\n",SVR_NAME);
	printf("Version   : %s\n",SVR_VERSION);
	printf("Build date: %s\n",SVR_BUILD_DATE);
	printf("Parent PID: %u\n\n",getpid());
}



#define NOTSET    "<not set>"
#define PRTSTR(S) (S ? S : NOTSET)

void printParams()
{
	char **ptr;
	int i;

	puts("Parameter values:");
	printf("   Config file       : %s\n",PRTSTR(config_file));
	printf("   MOTD file         : %s\n",PRTSTR(motd_file));
	printf("   Log file          : %s\n",PRTSTR(log_file));
	printf("   Network interface : %s\n",PRTSTR(iface));
	printf("   Port              : %d\n",port);
	printf("   Be daemon         : %s\n",
		(flags & FLAG_DAEMON) ? "YES" : "NO");
	printf("   Hexdump           : %s\n",
		(flags & FLAG_HEXDUMP) ? "YES" : "NO");
	printf("   Telopt timeout    : %d secs\n",telopt_timeout_secs);
	printf("   Login max attempts: %d\n",login_max_attempts);
	printf("   Login pause       : %d secs\n",login_pause_secs);
	printf("   Login timeout     : %d secs\n",login_timeout_secs);
	printf("   Login prompt      : ");
	if (login_prompt)
		printf("\"%s\"\n",login_prompt);
	else
		puts(NOTSET);
	printf("   Password prompt   : ");
	if (pwd_prompt)
		printf("\"%s\"\n",pwd_prompt);
	else
		puts(NOTSET);
	printf("   Banned users      : ");
	if (banned_users_cnt)
	{
		for(i=0;i < banned_users_cnt;++i)
		{
			if (i) putchar(',');
			printf("%s",banned_users[i]);
		}
		putchar('\n');
	}
	else puts("<none>");

	printf("   Login process args: ");
	if (login_exec_argv_cnt)
	{
                for(i=0;i < login_exec_argv_cnt;++i)
		{
			if (i) putchar(',');
			printf("%s",login_exec_argv[i]);
		}
		if (flags & FLAG_APPEND_USER)
			puts(",[TELNET USER]");
		else
			putchar('\n');
	}
	else if (shell_exec_argv) puts(NOTSET);
	else
	{
		printf("%s%s\n",
			LOGIN_PROG,
			(flags & FLAG_APPEND_USER) ? ",[TELNET USER]" : "");
	}
	printf("   Shell process args: ");
	if (shell_exec_argv)
	{
                for(ptr=shell_exec_argv;*ptr;++ptr)
		{
			if (ptr != shell_exec_argv) putchar(',');
			printf("%s",*ptr);
		}
		putchar('\n');
	}
	else puts(NOTSET);
}




/*** Create the socket to initially connect to ***/
void createListenSocket()
{
	struct sockaddr_in bind_addr;
	int on;

	if ((listen_sock = socket(AF_INET,SOCK_STREAM,0)) == -1)
	{
		perror("ERROR: createListenSocket(): socket()");
		exit(1);
	}

	on = 1;
	if (setsockopt(
		listen_sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) == -1)
	{
		perror("ERROR: createListenSocket(): setsockopt(SO_REUSEADDR)");
		exit(1);
	}

	if (iface)
	{
		printf("Interface \"%s\" has address %s\n",
			iface,inet_ntoa(iface_in_addr.sin_addr));
	}

	bzero(&bind_addr,sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(port);
	bind_addr.sin_addr.s_addr = iface_in_addr.sin_addr.s_addr;

	if (bind(
		listen_sock,
		(struct sockaddr *)&bind_addr,sizeof(bind_addr)) == -1)
	{
		perror("ERROR: createListenSocket(): bind()");
		exit(1);
	}

	if (listen(listen_sock,20) == -1)
	{
		perror("ERROR: createListenSocket(): listen()");
		exit(1);
	}
	printf("*** Listening on port %d ***\n",port);
}




/*** Does what it says on the tin ***/
void mainloop()
{
	struct linger lin;
	struct hostent *host;
	struct sockaddr_in ip_addr;
	socklen_t size;
	char *dns;

	parent_pid = getpid();

	/* Won't print if we're a daemon but whatever */
	if (log_file)
		printf("Redirecting output to log file \"%s\"...\n",log_file);
	else
		puts("Logging to stdout...");

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
			exit(1);
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
			break;
		}
		close(sock);
	}
}




void beDaemon()
{
	int i;

	/* If parent is init (pid 1) then we're already a daemon so don't
	   bother. Remember on reboot we only exec(), not fork() so parent
	   remains the same */
	if (getppid() == 1) return;

	printf("Becoming background daemon...\n");

	switch(fork())
	{
	case -1:
		fprintf(stderr,"ERROR: beDaemon(): fork(): %s\n",strerror(errno));
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

	/* Ignore any hang up signals */
	signal(SIGHUP,SIG_IGN);

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




void parentSigHandler(int sig)
{
	logprintf(parent_pid,"SIGNAL %d, exiting...\n",sig);
	close(listen_sock);
	exit(sig);
}
