/*****************************************************************************
 NJR-TelnetD

 A simple telnet daemon. Perhaps doesn't do all the telopt negotiation that
 it should. Linux and MacOS only.

 Original version written in December 2018
 *****************************************************************************/

#define MAINFILE
#include "globals.h"

#define LOGIN_PROMPT (char *)"login: "
#define PWD_PROMPT   (char *)"password: "

struct sockaddr_in iface_in_addr;
char *iface;
int port;
int listen_sock;

void parseCmdLine(int argc, char **argv);
void parseInterface(char *addr);
void version();
void createListenSocket();
void mainloop();
void beDaemon();
void parentSigHandler(int sig);


/*** START ***/
int main(int argc, char **argv)
{
	parseCmdLine(argc,argv);
	version();
	createListenSocket();
	if (flags & FLAG_DAEMON) beDaemon();
	mainloop();
	return 0;
}



/*** Guess ***/
void parseCmdLine(int argc, char **argv)
{
	int i;
	char c;

	port = PORT;
	login_prog = NULL;
	login_prompt = LOGIN_PROMPT;
	pwd_prompt = PWD_PROMPT;
	max_login_attempts = MAX_LOGIN_ATTEMPTS;
	login_pause_secs = LOGIN_PAUSE_SECS;
	login_timeout_secs = LOGIN_TIMEOUT_SECS;
	shell = NULL;
	motd_file = NULL;
	log_file = NULL;
	god_login = NULL;
	god_utmp_name = NULL;
	flags = 0;
	iface = NULL;
	iface_in_addr.sin_addr.s_addr = INADDR_ANY;

	for(i=1;i < argc;++i)
	{
		if (argv[i][0] != '-' || strlen(argv[i]) != 2) goto USAGE;
		c = argv[i][1];

		switch(c)
		{
		case 'd':
			flags |= FLAG_DAEMON;
			continue;
		case 'h':
			goto USAGE;
		case 'v':
			version();
			exit(0);
		case 'x':
			flags |= FLAG_HEXDUMP;
			continue;
#ifndef __APPLE__
		case 'r':
			flags |= FLAG_ALLOW_ROOT;
			continue;
#endif
		}

		if (++i == argc) goto USAGE;

		switch(c)
		{
#ifndef __APPLE__
		case '1':
			login_prompt = argv[i];
			break;
		case '2':
			pwd_prompt = argv[i];
			break;
		case 'a':
			max_login_attempts = atoi(argv[i]);
			break;
		case 'g':
			god_login = argv[i];
			bzero(&god_userinfo,sizeof(god_userinfo));
			god_userinfo.pw_dir = "/";
			break;
		case 's':
			shell = argv[i];
			break;
		case 't':
			login_timeout_secs = atoi(argv[i]);
			break;
		case 'u':
			login_pause_secs = atoi(argv[i]);
			break;
		case 'w':
			god_utmp_name = argv[i];
			break;
#endif
		case 'f':
			log_file = argv[i];
			break;
		case 'i':
			parseInterface(argv[i]);
			break;
		case 'l':
			login_prog = argv[i];
			break;
		case 'm':
			motd_file = argv[i];
			break;
		case 'p':
			port = atoi(argv[i]);
			break;
		default:
			goto USAGE;
		}
	}
	if (port < 1 || 
	    max_login_attempts < 1 || 
	    login_pause_secs < 0 || login_timeout_secs < 0) goto USAGE;

	if (shell)
	{
		if (login_prog)
		{
			puts("ERROR: The -s and -l options are mutually exclusive.");
			exit(1);
		}
	}
	else
	{
		if (login_prompt != LOGIN_PROMPT || pwd_prompt != PWD_PROMPT)
		{
			puts("ERROR: The -1 and -2 options require -s.");
			exit(1);
		}
		if (!login_prog) login_prog = LOGIN_PROG;
	}
	if (god_login)
		god_userinfo.pw_name = god_utmp_name ? god_utmp_name : god_login;
	return;

	USAGE:
	printf("Usage: %s\n"
	       "       -p <port>                : Default = %d\n"
	       "       -i <interface name or IP>: eg: 127.0.0.1 or lo0 for localhost only.\n"
	       "                                  Default = all interfaces\n"
	       "       -l <login program>       : Alternative login program.\n"
	       "                                  Default = \"%s\"\n"
	       "       -m <MOTD file>\n"
	       "       -f <log file>            : Default = stdout (unless running as daemon)\n"
#ifndef __APPLE__
	       "       -s <shell>               : Use built-in login system and exec this shell.\n"
	       "                                  Default = none.\n"
	       "       -1 <string>              : Alternative login prompt.\n"
	       "       -2 <string>              : Alternative password prompt.\n"
	       "       -g <god login name>      : For -s only. When this login is used the user\n"
	       "                                  is logged in as root. The user does not have\n"
	       "                                  to exist on the system.\n"
	       "       -w <god who name>        : If -g used this sets name seen in 'who' else\n"
	       "                                  the god login name is used.\n"
	       "       -a <max login attempts>  : For -s only. Default = %d\n"
	       "       -t <login timeout secs>  : For -s only. Seconds until user is timed out\n"
	       "                                  at the login prompt if nothing entered.\n"
	       "                                  Default = %d\n"
	       "       -u <login pause secs>    : For -s only. Seconds until next login prompt\n"
	       "                                  if incorrect password entered. Default = %d\n"
	       "       -r                       : For -s only. Allow root logins.\n"
#endif
	       "       -d                       : Run as background daemon.\n"
	       "       -x                       : Hexdump all RX from socket to log.\n"
	       "       -h                       : Show this usage info.\n"
	       "       -v                       : Print version then exit.\n"
	       "Note: All arguments are optional.\n",
#ifdef __APPLE__
		argv[0],PORT,LOGIN_PROG);
#else
		argv[0],
		PORT,
		LOGIN_PROG,
		MAX_LOGIN_ATTEMPTS,
		LOGIN_PAUSE_SECS,
		LOGIN_TIMEOUT_SECS);
#endif
	exit(1);
}




void parseInterface(char *addr)
{
	struct ifaddrs *addr_list;
	struct ifaddrs *entry;

	/* Valid IP address or interface name? */
	if ((iface_in_addr.sin_addr.s_addr = inet_addr(addr)) != -1) return;

	iface = addr;
	if (getifaddrs(&addr_list) == -1)
	{
		perror("ERROR: getifaddrs()");
		exit(1);
	}
	/* Match interface name */
	for(entry=addr_list;entry;entry=entry->ifa_next)
	{
		/* IP4 only for now */
		if (!strcmp(iface,entry->ifa_name) &&
		    entry->ifa_addr->sa_family == AF_INET)
		{
			memcpy(&iface_in_addr,entry->ifa_addr,sizeof(iface_in_addr));
			return;
		}
	}
	printf("ERROR: Interface '%s' does not exist or is not IP4.\n",iface);
	exit(1);
}




void version()
{
	printf("\n*** %s ***\n\n",SVR_NAME);
	printf("Version   : %s\n",SVR_VERSION);
	printf("Build date: %s\n",SVR_BUILD_DATE);
	printf("Parent PID: %u\n\n",getpid());
}




/*** Create the socket to initially connect to ***/
void createListenSocket()
{
	struct sockaddr_in bind_addr;
	int on;

	if ((listen_sock = socket(AF_INET,SOCK_STREAM,0)) == -1)
	{
		perror("ERROR: socket()");
		exit(1);
	}

	on = 1;
	if (setsockopt(
		listen_sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) == -1)
	{
		perror("ERROR: setsockopt(SO_REUSEADDR)");
		exit(1);
	}

	bzero(&bind_addr,sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(port);
	bind_addr.sin_addr.s_addr = iface_in_addr.sin_addr.s_addr;

	if (bind(
		listen_sock,
		(struct sockaddr *)&bind_addr,sizeof(bind_addr)) == -1)
	{
		perror("ERROR: bind()");
		exit(1);
	}

	if (listen(listen_sock,20) == -1)
	{
		perror("ERROR: listen()");
		exit(1);
	}
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
	if (iface)
	{
		logprintf(parent_pid,"Interface '%s' has address %s\n",
			iface,inet_ntoa(iface_in_addr.sin_addr));
	}
	logprintf(parent_pid,"Listening on port %d\n",port);

	/* Don't want to do a wait() on zombies */
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

	size = sizeof(ip_addr);
	lin.l_onoff = 1;
	lin.l_linger = 1;

	/* Sit in accept and just fork off a child when it returns */
	while(1)
	{
		if ((sock = accept(
			listen_sock,(struct sockaddr *)&ip_addr,&size)) == -1)
		{
			perror("ERROR: accept()");
			exit(1);
		}

		if (setsockopt(
			sock,
			SOL_SOCKET,SO_LINGER,(char *)&lin,sizeof(lin)) == -1)
		{
			perror("ERROR: setsockopt(SO_LINGER)");
			exit(1);
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
			perror("ERROR: fork()");
			close(sock);
			exit(1);

		case 0:
			close(listen_sock);
			childMain();
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

	logprintf(getpid(),"Becoming background daemon...\n");

	switch(fork())
	{
	case -1:
		logprintf(getpid(),"ERROR: fork(): %s\n",strerror(errno));
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

	logprintf(parent_pid,"Running as daemon.\n");
}




void parentSigHandler(int sig)
{
	logprintf(parent_pid,"SIGNAL %d, exiting...\n",sig);
	close(listen_sock);
	exit(sig);
}
