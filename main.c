/*****************************************************************************
 NJR-TelnetD

 A simple telnet daemon. Perhaps doesn't do all the telopt negotiation that
 it should. Linux and MacOS only.

 Original version written in December 2018
 *****************************************************************************/

#define MAINFILE
#include "globals.h"

#define CONFIG_FILE "telnetd.cfg"

static void init(int restart);
static void clear(void);
static void parseCmdLine(int argc, char **argv);
static void version(void);
static void beDaemon(void);
static void setSignals(void);
static void doChecks(void);
static void mainloop(void);
static void sigHUPHandler(int sig, siginfo_t *siginfo, void *pcontext);
static void sigExitHandler(int sig, siginfo_t *siginfo, void *pcontext);


/*********************************** INIT ***********************************/

int main(int argc, char **argv)
{
	int first = 1;

	while(1)
	{
		init(first);
		parseCmdLine(argc,argv);
		version();
		parseConfigFile();
		doChecks();
		createListenSocket();
		if (flags.daemon_tmp)
		{
			beDaemon();
			/* Set this late so logprintf() works during boot */
			flags.daemon = 1;
		}
		setSignals();

		/* mainloop() will only ever exit on a SIGHUP which means do a
		   restart and re-read the config file */
		mainloop();
		clear();
		logprintf(master_pid,"*** RESTART ***");
		first = 0;
	}
	return 0;
}



void init(int first)
{
	/* Don't clear the log file if we're restarting or the messages will
	   disappear into a black hole if we're running as a daemon */
	if (first) log_file = NULL;
	pwd_file = NULL;
	config_file = CONFIG_FILE;
	port = PORT;
	login_prompt = NULL;
	pwd_prompt = NULL;
	login_incorrect_msg = NULL;
	login_max_attempts_msg = NULL;
	login_svrerr_msg = NULL;
	login_timeout_msg = NULL;
	banned_user_msg = NULL;
	banned_ip_msg = NULL;
	login_max_attempts = LOGIN_MAX_ATTEMPTS;
	login_pause_secs = LOGIN_PAUSE_SECS;
	login_timeout_secs = LOGIN_TIMEOUT_SECS;
	telopt_timeout_secs = TELOPT_TIMEOUT_SECS;
	banned_users = NULL;
	banned_users_cnt = 0;
	shell_exec_argv = NULL;
	shell_exec_argv_cnt = 0;
	login_exec_argv = NULL;
	login_exec_argv_cnt = 0;
	log_file_max_fails = LOG_FILE_MAX_FAILS;
	log_file_fail_cnt = 0;
	pre_motd_file = NULL;
	post_motd_file = NULL;
	iface = NULL;
	iface_in_addr.sin_addr.s_addr = INADDR_ANY;
	listen_sock = 0;
	state = STATE_NOTSET;
	parent_pid = getpid();
	username[0] = 0;
	iplist = NULL;
	iplist_cnt = 0;
	iplist_type = IP_NO_LIST;

	bzero(&flags,sizeof(flags));
}




void clear(void)
{
	int i;

	close(listen_sock);
	FREE(login_prompt);
	FREE(pwd_prompt);
	FREE(login_incorrect_msg);
	FREE(login_max_attempts_msg);
	FREE(login_svrerr_msg);
	FREE(login_timeout_msg);
	FREE(banned_user_msg);
	FREE(banned_ip_msg);
	FREE(pre_motd_file);
	FREE(post_motd_file);

	/* Only clear password file, not log file otherwise logging will
	   suddenly stop */
	FREE(pwd_file);

	for(i=0;i < shell_exec_argv_cnt;++i) free(shell_exec_argv[i]);
	FREE(shell_exec_argv);

	for(i=0;i < login_exec_argv_cnt;++i) free(login_exec_argv[i]);
	FREE(login_exec_argv);

	for(i=0;i < banned_users_cnt;++i) free(banned_users[i]);
	FREE(banned_users);

	for(i=0;i < iplist_cnt;++i) free(iplist[i]);
	FREE(iplist);
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




void version(void)
{
	logprintf(0,"\n*** %s ***\n\n",SVR_NAME);
	logprintf(0,"Version   : %s\n",SVR_VERSION);
	logprintf(0,"Build     : ");
#ifdef __APPLE__
	logprintf(0,"MacOS\n");
#else
	logprintf(0,"Linux/generic\n");
#endif
	logprintf(0,"Build date: %s\n",BUILD_DATE);
	logprintf(0,"Parent PID: %u\n\n",getpid());
}




/**** User id and crypt() check ***/
void doChecks(void)
{
#ifndef __APPLE__
	enum
	{
		ENC_DES,
		ENC_MD5,
		ENC_SHA256,
		ENC_SHA512,
		ENC_BLOWFISH,

		NUM_ENC_METHODS
	};
	char *enc_code[NUM_ENC_METHODS] =
	{
		"","1","2a","5","6"
	};
	char *enc_name[NUM_ENC_METHODS] =
	{
		"DES",
		"MD5",
		"SHA256",
		"SHA512",
		"BLOWFISH"
	};
	char salt[7];
	char *ptr;
	int i;
#endif
	if (getuid())
	{
		logprintf(0,"WARNING: Running as uid %d not root. Some functionality may not be available.\n",getuid());
	}

	/*** See which cryptographic functions are supported by crypt(). Just 
	     prints warnings to the log ***/
	if (pwd_file)
	{
#ifdef __APPLE__
		logprintf(0,"WARNING: MacOS crypt() only supports DES encryption.\n");
#else
		/* See what glibc supports */
		logprintf(0,">>> Non DES encryption types supported by crypt():\n");
		for(i=0;i < NUM_ENC_METHODS;++i)
		{
			sprintf(salt,"$%s$ab",enc_code[i]);
			ptr = crypt("x",salt);
			logprintf(0,"    %-8s: %s\n",
				enc_name[i],
				(!ptr || (i == ENC_BLOWFISH && ptr[3] != '$')) ? "NO" : "YES");
		}
#endif
	}
}




void beDaemon(void)
{
	int i;

	/* If parent is init (pid 1) then we're already a daemon so don't
	   bother. Remember on reboot we only exec(), not fork() so parent
	   remains the same */
	if (getppid() == 1) return;

	logprintf(0,">>> Becoming background daemon...\n");

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




void setSignals(void)
{
	struct sigaction sa;
	sigset_t sigmask;

	/* Not going to bother to reap in the parent process */
	signal(SIGCHLD,SIG_IGN);
        
 	/* Block SIGUSR1 so we can sigwait() on it. Set others to point at 
	   handler */
	sigemptyset(&usr1_sigmask);
	sigaddset(&usr1_sigmask,SIGUSR1);
	sigprocmask(SIG_BLOCK,&usr1_sigmask,NULL);

	/* SIGHUP causes a restart. Using sigaction() instead of signal()
	   because signal() sets SA_RESTART meaning the accept() call won't 
	   exit when this signal is received. We want it to exit. */
	sigemptyset(&sigmask);
	bzero(&sa,sizeof(sa));
	sa.sa_mask = sigmask;
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = sigHUPHandler;
	sigaction(SIGHUP,&sa,NULL);

	/* Exit handlers */
	sa.sa_sigaction = sigExitHandler;
	sigaction(SIGINT,&sa,NULL);
	sigaction(SIGQUIT,&sa,NULL);
	sigaction(SIGTERM,&sa,NULL);
}       




/********************************* RUNTIME **********************************/

/*** Does what it says on the tin ***/
void mainloop(void)
{
	struct sockaddr_in ip_addr;
	struct linger lin;
	socklen_t size;

	logprintf(parent_pid,"STARTED: Parent process.\n");

	size = sizeof(ip_addr);
	lin.l_onoff = 1;
	lin.l_linger = 1;

	/* Sit in accept and just fork off a child when it returns */
	while(1)
	{
		if ((sock = accept(
			listen_sock,(struct sockaddr *)&ip_addr,&size)) == -1)
		{
			if (errno == EINTR)
			{
				if (flags.rx_sighup) return;
				if (flags.ignore_sighup) continue;
			}

			/* This is fairly terminal , just die */
			logprintf(parent_pid,"ERROR: mainloop(): accept(): %s\n",
				strerror(errno));
			parentExit(-1);
		}

		strcpy(ipaddrstr,inet_ntoa(ip_addr.sin_addr));

		logprintf(parent_pid,"CONNECTION: Socket = %d, IP = %s\n",
			sock,ipaddrstr);

		/* See if IP in white/black list. Do this before we waste cycles
		   doing a fork  */
		if (!authorisedIP(ipaddrstr))
		{
			logprintf(parent_pid,"CONNECTION REFUSED: Banned IP address.\n");
			if (banned_ip_msg) sockprintf("%s\r\n",banned_ip_msg);
			close(sock);
			continue;
		}

		if (setsockopt(
			sock,
			SOL_SOCKET,SO_LINGER,(char *)&lin,sizeof(lin)) == -1)
		{
			logprintf(parent_pid,"WARNING: mainloop(): setsockopt(SO_LINGER): %s\n",
				strerror(errno));
		}

		switch(fork())
		{
		case -1:
			logprintf(parent_pid,"ERROR: mainloop(): fork(): %s\n",
				strerror(errno));
			break;
		case 0:
			signal(SIGHUP,SIG_IGN);
			close(listen_sock);
			runMaster(&ip_addr);
			break;
		default:
			break;
		}
		close(sock);
	}
}




void sigHUPHandler(int sig, siginfo_t *siginfo, void *pcontext)
{
	if (flags.ignore_sighup)
	{
		logprintf(parent_pid,"SIGNAL %d (%s) from pid %d: Ignoring.\n",
			sig,strsignal(sig),siginfo->si_pid);
		return;
	}
	logprintf(parent_pid,"SIGNAL %d (%s) from pid %d: Restarting...\n",
		sig,strsignal(sig),siginfo->si_pid);
	flags.rx_sighup = 1;
}




void sigExitHandler(int sig, siginfo_t *siginfo, void *pcontext)
{
	logprintf(parent_pid,"SIGNAL %d (%s) from pid %d: Exiting...\n",
		sig,strsignal(sig),siginfo->si_pid);
	close(listen_sock);
	parentExit(sig);
}
