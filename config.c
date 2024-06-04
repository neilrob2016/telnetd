#include "globals.h"

#define LOGIN_PROMPT "login: "
#define PWD_PROMPT   "password: "

#define LOGIN_INCORRECT_MSG    "Login incorrect."
#define LOGIN_MAX_ATTEMPTS_MSG "Maximum login attempts reached."
#define LOGIN_SVRERR_MSG       "Server error. Contact your system administrator."
#define LOGIN_TIMEOUT_MSG      "Timeout."
#define BANNED_USER_MSG        "Login banned."

#define SET_STR_FIELD(P) \
	if (P) \
	{ \
		if (flags.rx_sighup) \
			free(P); \
		else \
			goto ALREADY_SET_ERROR; \
	} \
	P = strdup(value);


static void processConfigParam(char **words, int word_cnt, int linenum);
static void parseBannedUsers(char *list);
static void parseInterface(char *addr);
static void parseIPList(char **words, int word_cnt);
static void printParams(void);


/*** If the config file is bad parseConfigFile() or processConfigParam() will 
     terminate the process even if we're re-reading via SIGHUP as rescuing the
     system from a partially parsed config is a lot of hassle involving temp 
     config variables. logprintf(0,... because only the parent process runs
     the following functions and we don't want the preamble printed in the
     boot up messages or when reparsing the config. */
void parseConfigFile(void)
{
	struct stat fs;
	char *map_start;
	char *map_end;
	char *ptr;
	char **words;
	int word_cnt;
	int linenum;
	int seek_nl;
	int fd;

	logprintf(0,">>> Parsing config file \"%s\"...\n",config_file);

	if ((fd=open(config_file,O_RDWR,0666)) == -1)
	{
		logprintf(0,"ERROR: parseConfigFile(): open(): %s\n",
			strerror(errno));
		parentExit(-1);
	}
	if (fstat(fd,&fs) == -1)
	{
		logprintf(0,"ERROR: parseConfigFile(): fstat(): %s\n",
			strerror(errno));
		parentExit(-1);
	}
	/* st_size + 1 so we can put \0 on end */
	if ((map_start = (char *)mmap(NULL,
		fs.st_size+1,
		PROT_READ | PROT_WRITE,MAP_PRIVATE,fd,0)) == MAP_FAILED)
	{
		logprintf(0,"ERROR: parseConfigFile(): mmap(): %s\n",
			strerror(errno));
		parentExit(-1);
	}
	close(fd);

	map_end = map_start + fs.st_size;
	linenum = 1;
	seek_nl = 0;

	/* Free the arrays */
	if (flags.rx_sighup)
	{
		if (shell_exec_argv)
		{
			freeWordArray(shell_exec_argv,shell_exec_argv_cnt);
			shell_exec_argv = NULL;
			shell_exec_argv_cnt = 0;
		}
		if (login_exec_argv)
		{
			freeWordArray(login_exec_argv,login_exec_argv_cnt);
			login_exec_argv = NULL;
			login_exec_argv_cnt = 0;
		}
		if (banned_users)
		{
			freeWordArray(banned_users,banned_users_cnt);
			banned_users = NULL;
			banned_users_cnt = 0;
		}
	}

	/* Find and process each line */
	for(ptr=map_start;ptr < map_end;)
	{
		if (*ptr == '\n')
		{
			++linenum;
			seek_nl = 0;
			++ptr;
		}
		else if (*ptr > 32 && !seek_nl)
		{
			seek_nl = 1;

			ptr = splitString(ptr,map_end,&words,&word_cnt);
			switch(word_cnt)
			{
			case -1:
				logprintf(0,"ERROR: Missing quotes with parameter \"%s\" on line %d.\n",
					words[0],linenum);
				parentExit(-1);
			case 0:
				break;
			default:
				processConfigParam(words,word_cnt,linenum);
				break;
			}
			freeWordArray(words,word_cnt);
		}
		else ++ptr;
	}
	munmap(map_start,fs.st_size+1);

	/* Do some sanity checks on the main fields */
	if (shell_exec_argv && login_exec_argv)
	{
		logprintf(0,"ERROR: The shell_program and login_program fields are mutually exclusive.\n");
		parentExit(-1);
	}
	if (pwd_file)
	{
		if (login_exec_argv)
		{
			logprintf(0,"ERROR: The login_program and pwd_file fields are mutually exclusive.\n");
			parentExit(1);
		}
 		if (!shell_exec_argv)
			logprintf(0,"WARNING: The pwd_file field is set but shell_program field is not.\n");
	}
#ifdef __APPLE__
	/* Require our own password file as we can't get user password info 
	   from MacOS as it doesn't have the getpwnam() system function, it 
	   uses PAM instead which is a PITA and doesn't seem to be designed
	   as a backend API */
	if (shell_exec_argv && !pwd_file)
	{
		logprintf(0,"ERROR: On MacOS the shell_program option requires the pwd_file option to be set.\n");
		parentExit(1);
	}
#endif
	/* Need strdup because they're strdup()'d if they come from the config
	   file and these will be free'd after SIGHUP so can't just point them
	   direct to the macros */
	if (!login_prompt) login_prompt = strdup(LOGIN_PROMPT);
	if (!pwd_prompt) pwd_prompt = strdup(PWD_PROMPT);
	if (!login_incorrect_msg)
		login_incorrect_msg = strdup(LOGIN_INCORRECT_MSG);
	if (!login_max_attempts_msg)
		login_max_attempts_msg = strdup(LOGIN_MAX_ATTEMPTS_MSG);
	if (!login_svrerr_msg) login_svrerr_msg = strdup(LOGIN_SVRERR_MSG);
	if (!login_timeout_msg) login_timeout_msg = strdup(LOGIN_TIMEOUT_MSG);
	if (!banned_user_msg) banned_user_msg = strdup(BANNED_USER_MSG);

	printParams();
}




void processConfigParam(char **words, int word_cnt, int linenum)
{
	enum
	{
		/* 0 Flags */
		FIELD_BE_DAEMON,
		FIELD_HEXDUMP,
		FIELD_LOGIN_APPEND_USER,
		FIELD_LOGIN_PRESERVE_ENV,
		FIELD_PWD_ASTERISKS,

		/* 5 */
		FIELD_DNS_LOOKUP,
		FIELD_STORE_HOST_IN_UTMP,
		FIELD_SHOW_TERM_RESIZE,
		FIELD_IGNORE_SIGHUP,

		/* Numeric */
		FIELD_PORT,
		/* 10 */
		FIELD_TELOPT_TIMEOUT_SECS,
		FIELD_LOG_FILE_MAX_FAILS,
		FIELD_LOGIN_MAX_ATTEMPTS,
		FIELD_LOGIN_TIMEOUT_SECS,
		FIELD_LOGIN_PAUSE_SECS,

		/* 15 Strings */
		FIELD_NETWORK_INTERFACE,
		FIELD_LOGIN_PROGRAM,
		FIELD_LOGIN_PROMPT,
		FIELD_LOGIN_INCORRECT_MSG,
		FIELD_LOGIN_MAX_ATTEMPTS_MSG,

		/* 20 */
		FIELD_LOGIN_SVRERR_MSG,
		FIELD_LOGIN_TIMEOUT_MSG,
		FIELD_PWD_PROMPT,
		FIELD_SHELL_PROGRAM,
		FIELD_BANNED_USERS,

		/* 25 */
		FIELD_BANNED_USER_MSG,
		FIELD_MOTD_FILE,
		FIELD_PRE_MOTD_FILE,
		FIELD_POST_MOTD_FILE,
		FIELD_LOG_FILE,

		/* 30 */
		FIELD_LOG_FILE_RM,
		FIELD_PWD_FILE,
		FIELD_IP_WHITELIST,
		FIELD_IP_BLACKLIST,
		FIELD_IP_BANNED_MSG,

		NUM_PARAMS
	};
	const char *params[NUM_PARAMS] =
	{
		/* 0 Flags */
		"be_daemon",
		"hexdump",
		"login_append_user",
		"login_preserve_env",
		"pwd_asterisks",

		/* 5 */
		"dns_lookup",
		"store_host_in_utmp",
		"show_term_resize",
		"ignore_sighup",

		/* Numeric values */
		"port",
		/* 10 */
		"telopt_timeout_secs",
		"log_file_max_fails",
		"login_max_attempts",
		"login_timeout_secs",
		"login_pause_secs",

		/* 15 String values */
		"network_interface",
		"login_program",
		"login_prompt",
		"login_incorrect_msg",
		"login_max_attempts_msg",

		/* 20 */
		"login_svrerr_msg",
		"login_timeout_msg",
		"pwd_prompt",
		"shell_program",
		"banned_users",

		/* 25 */
		"banned_user_msg",
		"motd_file",
		"pre_motd_file",
		"post_motd_file",
		"log_file",

		/* 30 */
		"log_file_rm",
		"pwd_file",
		"ip_whitelist",
		"ip_blacklist",
		"banned_ip_msg"
	};
	char *param = words[0];
	char *value = words[1];
	char *ptr;
	char *tmp;
	int is_num;
	int ivalue;
	int yes;
	int i;

	logprintf(0,"    Line %-2d: \"%s\": ",linenum,param);

	/* Check for numeric value */
	for(ptr=value;*ptr && isdigit(*ptr);++ptr);
	if (*ptr) is_num = 0;
	else
	{
		is_num = 1;
		ivalue = atoi(value);
	}

	for(i=0;i < NUM_PARAMS;++i)
	{
		if (strcmp(param,params[i])) continue;

		switch(i)
		{
		case FIELD_IP_WHITELIST:
		case FIELD_IP_BLACKLIST:
			break;
		default:
			if (word_cnt > 2)
			{
				logprintf(0,"ERROR: Too many arguments (%d) for field.\n",word_cnt);
				parentExit(-1);
			}
		}

		if (is_num) yes = -1;
		else if (!strcasecmp(value,"YES") || !strcasecmp(value,"TRUE"))
			yes = 1;
		else if (!strcasecmp(value,"NO") || !strcasecmp(value,"FALSE"))
			yes = 0;
		else yes = -1;

		switch(i)
		{
		/* Flags */
		case FIELD_BE_DAEMON:
			if (flags.rx_sighup) goto IGNORE_WARNING; /* Too late */
			if (yes == -1) goto VAL_ERROR;
			flags.daemon = yes;
			break;

		case FIELD_HEXDUMP:
			if (yes == -1) goto VAL_ERROR;
			flags.hexdump = yes;
			break;

		case FIELD_LOGIN_APPEND_USER:
			if (yes == -1) goto VAL_ERROR;
			flags.append_user = yes;
			break;

		case FIELD_LOGIN_PRESERVE_ENV:
			if (yes == -1) goto VAL_ERROR;
			flags.preserve_env = yes;
			break;

		case FIELD_PWD_ASTERISKS:
			if (yes == -1) goto VAL_ERROR;
			flags.pwd_asterisks = yes;
			break;

		case FIELD_DNS_LOOKUP:
			if (yes == -1) goto VAL_ERROR;
			flags.dns_lookup = yes;
			break;

		case FIELD_STORE_HOST_IN_UTMP:
			if (yes == -1) goto VAL_ERROR;
			flags.store_host_in_utmp = yes;
			break;

		case FIELD_SHOW_TERM_RESIZE:
			if (yes == -1) goto VAL_ERROR;
			flags.show_term_resize = yes;
			break;

		case FIELD_IGNORE_SIGHUP:
			if (yes == -1) goto VAL_ERROR;
			flags.ignore_sighup = yes;
			break;

		/* Numeric values */
		case FIELD_PORT:
			/* Ignore if SIGHUP as it would mean closing the
			   current socket and re-creating. Too much hassle. */
			if (flags.rx_sighup) goto IGNORE_WARNING;
			if (!is_num || ivalue < 1 || ivalue > 0xFFFF)
				goto VAL_ERROR;
			port = ivalue;
			break;

		case FIELD_TELOPT_TIMEOUT_SECS:
			if (!is_num || ivalue < 0) goto VAL_ERROR;
			telopt_timeout_secs = ivalue;
			break;

		case FIELD_LOG_FILE_MAX_FAILS:
			if (!is_num || ivalue < 0) goto VAL_ERROR;
			if (flags.log_fails_override) goto OVERRIDE;
			log_file_max_fails = ivalue;
			break;

		case FIELD_LOGIN_MAX_ATTEMPTS:
			if (!is_num || ivalue < 1) goto VAL_ERROR;
			login_max_attempts = ivalue;
			break;

		case FIELD_LOGIN_SVRERR_MSG:
			SET_STR_FIELD(login_svrerr_msg);
			break;

		case FIELD_LOGIN_TIMEOUT_MSG:
			SET_STR_FIELD(login_timeout_msg);
			break;

		case FIELD_LOGIN_TIMEOUT_SECS:
			if (!is_num || ivalue < 1) goto VAL_ERROR;
			login_timeout_secs = ivalue;
			break;

		case FIELD_LOGIN_PAUSE_SECS:
			if (!is_num || ivalue < 0) goto VAL_ERROR;
			login_pause_secs = ivalue;
			break;

		/* String values */
		case FIELD_NETWORK_INTERFACE:
			if (flags.rx_sighup) goto IGNORE_WARNING;
			parseInterface(value);
			break;

		case FIELD_LOGIN_PROGRAM:
			if (login_exec_argv) goto ALREADY_SET_ERROR;
			splitString(
				value,
				NULL,&login_exec_argv,&login_exec_argv_cnt);
			if (login_exec_argv_cnt < 1)
			{
				logprintf(0,"ERROR: Empty or invalid login_program string on line %d.\n",linenum);
				parentExit(-1);
			}
			parsePath(&login_exec_argv[0]);
			break;

		case FIELD_LOGIN_PROMPT:
			SET_STR_FIELD(login_prompt);
			break;

		case FIELD_LOGIN_INCORRECT_MSG:
			SET_STR_FIELD(login_incorrect_msg);
			break;

		case FIELD_LOGIN_MAX_ATTEMPTS_MSG:
			SET_STR_FIELD(login_max_attempts_msg);
			break;

		case FIELD_PWD_PROMPT:
			SET_STR_FIELD(pwd_prompt);
			break;

		case FIELD_SHELL_PROGRAM:
			if (shell_exec_argv) goto ALREADY_SET_ERROR;
			splitString(
				value,NULL,
				&shell_exec_argv,&shell_exec_argv_cnt);
			if (shell_exec_argv_cnt < 1)
			{
				logprintf(0,"ERROR: Empty or invalid shell_program string on line %d.\n",linenum);
				parentExit(-1);
			}
			parsePath(&shell_exec_argv[0]);
			break;

		case FIELD_BANNED_USERS:
			if (banned_users && !flags.rx_sighup)
				goto ALREADY_SET_ERROR;
			parseBannedUsers(value);
			break;

		case FIELD_BANNED_USER_MSG:
			SET_STR_FIELD(banned_user_msg);
			break;

		case FIELD_MOTD_FILE:
		case FIELD_PRE_MOTD_FILE:
			SET_STR_FIELD(pre_motd_file);
			parsePath(&pre_motd_file);
			break;

		case FIELD_POST_MOTD_FILE:
			SET_STR_FIELD(post_motd_file);
			parsePath(&post_motd_file);
			break;
		
		case FIELD_LOG_FILE:
		case FIELD_LOG_FILE_RM:
			if (flags.rx_sighup) goto IGNORE_WARNING;
			if (flags.log_file_override) goto OVERRIDE;

			/* Print OK before setting the log file or at startup 
			   we'll have the "Line" number on stdout and the OK
			   in the log file */
			logprintf(0,"OK\n");
			tmp = strdup(value);
			parsePath(&tmp);
			logprintf(0,">>> Redirecting output to \"%s\"...\n",tmp);
			log_file = tmp;
			if (i == FIELD_LOG_FILE_RM) unlink(log_file);
			return;

		case FIELD_PWD_FILE:
			SET_STR_FIELD(pwd_file);
			parsePath(&pwd_file);
			break;

		case FIELD_IP_WHITELIST:
			switch(iplist_type)
			{
			case IP_NO_LIST:
				break;
			case IP_WHITELIST:
				goto ALREADY_SET_ERROR;
			case IP_BLACKLIST:
				goto IPLIST_ERROR;
			}
			iplist_type = IP_WHITELIST;
			/* Fall through */

		case FIELD_IP_BLACKLIST:
			if (i == FIELD_IP_BLACKLIST)
			{
				switch(iplist_type)
				{
				case IP_NO_LIST:
					break;
				case IP_WHITELIST:
					goto IPLIST_ERROR;
				case IP_BLACKLIST:
					goto ALREADY_SET_ERROR;
				}
				iplist_type = IP_BLACKLIST;
			}
			parseIPList(words,word_cnt);
			break;

		case FIELD_IP_BANNED_MSG:
			SET_STR_FIELD(banned_ip_msg);
			break;

		default:
			assert(0);
		}
		logprintf(0,"OK\n");
		return;
	}
	if (i == NUM_PARAMS)
	{
		logprintf(0,"ERROR: Unknown parameter.\n");
		parentExit(-1);
	}

	VAL_ERROR:
	logprintf(0,"ERROR: Invalid value \"%s\".\n",value);
	parentExit(-1);

	ALREADY_SET_ERROR:
	logprintf(0,"ERROR: Field already set.\n");
	parentExit(-1);

	IPLIST_ERROR:
	logprintf(0,"ERROR: The whitelist and blacklist fields are mutually exclusive.\n");
	parentExit(-1);

	IGNORE_WARNING:
	logprintf(0,"WARNING: Field \"%s\" ignored - valid at startup only.\n",param);
	return;
	
	OVERRIDE:
	logprintf(0,"WARNING: Field \"%s\" overridden by command line argument.\n",param);
	return;
}




void parseBannedUsers(char *list)
{
	char *user;
	int i;

	if (flags.rx_sighup && banned_users)
	{
		for(i=0;i < banned_users_cnt;++i) free(banned_users[i]);
		free(banned_users);
	}
	for(user=strtok(list,",");user;user=strtok(NULL,","))
	{
		banned_users = (char **)realloc(
			banned_users,(banned_users_cnt + 1) * sizeof(char *));
		assert(banned_users);

		banned_users[banned_users_cnt] = strdup(user);
		assert(banned_users[banned_users_cnt]);

		++banned_users_cnt;
	} 
}




void parseInterface(char *addr)
{
	struct ifaddrs *addr_list;
	struct ifaddrs *entry;

	/* Valid IP address or interface name? */
	if ((int)(iface_in_addr.sin_addr.s_addr = inet_addr(addr)) != -1) return;

	iface = strdup(addr);
	if (getifaddrs(&addr_list) == -1)
	{
		logprintf(0,"ERROR: parseInterface(): getifaddrs(): %s\n",
			strerror(errno));
		parentExit(-1);
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
	logprintf(0,"ERROR: Interface \"%s\" does not exist or is not IP4.\n",iface);
	parentExit(-1);
}




void parseIPList(char **words, int word_cnt)
{
	int i;
	for(i=1;i < word_cnt;++i) addToIPList(words[i]);
}




#define NOTSET    "<not set>\n"
#define PRTSTR(S) (S ? S : "<not set>")
#define YESNO(F)  (F ? "YES" : "NO")

void printParams(void)
{
	int i;

	/* Don't need parent id as we're doing short log lines */
	logprintf(0,"\n    Parameter               Value\n");
	logprintf(0,"    =========               =====\n");
	logprintf(0,"    Config file           : %s\n",PRTSTR(config_file));
	logprintf(0,"    Pre login MOTD file   : %s\n",PRTSTR(pre_motd_file));
	logprintf(0,"    Post login MOTD file  : %s\n",PRTSTR(post_motd_file));
	logprintf(0,"    Password file         : %s\n",PRTSTR(pwd_file));
	logprintf(0,"    Log file              : %s\n",PRTSTR(log_file));
	logprintf(0,"    Log file max wrt fails: %d\n",log_file_max_fails);
	logprintf(0,"    Network interface     : %s\n",PRTSTR(iface));
	logprintf(0,"    Port                  : %d\n",port);
	logprintf(0,"    Telopt timeout        : %d secs\n",telopt_timeout_secs);
	logprintf(0,"    Be daemon             : %s\n",YESNO(flags.daemon));
	logprintf(0,"    Hexdump               : %s\n",YESNO(flags.hexdump));
	logprintf(0,"    Do DNS lookup         : %s\n",YESNO(flags.dns_lookup));
	logprintf(0,"    Ignore SIGHUP         : %s\n",YESNO(flags.ignore_sighup));
	if (!shell_exec_argv)
		logprintf(0,"    Login append user     : %s\n",YESNO(flags.append_user));

	if (login_exec_argv)
	{
		logprintf(0,"    Login exec arguments  : ");
                for(i=0;i < login_exec_argv_cnt;++i)
		{
			if (i) logprintf(0,",");
			logprintf(0,"%s",login_exec_argv[i]);
		}
		if (flags.append_user)
			logprintf(0,",[TELNET USER]\n\n");
		else
			logprintf(0,"\n\n");
		return;
	}
	if (!shell_exec_argv)
	{
		/* Will be calling default LOGIN_PROG */
		logprintf(0,"    Login preserve env    : %s\n",
			YESNO(flags.preserve_env));
		logprintf(0,"    Login exec arguments  : %s%s%s\n\n",
			LOGIN_PROG,
			flags.preserve_env ? ",-p" : "",
			flags.append_user ? ",[TELNET USER]" : "");
		return;
	}

	/* The rest only apply if the shell_program field is set */
	logprintf(0,"    Shell exec arguments  : ");
	for(i=0;i < shell_exec_argv_cnt;++i)
	{
		if (i) logprintf(0,",");
		logprintf(0,"%s",shell_exec_argv[i]);
	}
	logprintf(0,"\n    Login prompt          : ");
	if (login_prompt)
		logprintf(0,"\"%s\"\n",login_prompt);
	else
		logprintf(0,NOTSET);
	logprintf(0,"    Password prompt       : ");
	if (pwd_prompt)
		logprintf(0,"\"%s\"\n",pwd_prompt);
	else
		logprintf(0,NOTSET);
	logprintf(0,"    Password asterisks    : %s\n",YESNO(flags.pwd_asterisks));
	logprintf(0,"    Store host in utmp    : %s\n",YESNO(flags.store_host_in_utmp));
	logprintf(0,"    Show terminal resize  : %s\n",YESNO(flags.show_term_resize));
	logprintf(0,"    Login incorrect msg   : \"%s\"\n",login_incorrect_msg);
	logprintf(0,"    Login server error msg: \"%s\"\n",login_svrerr_msg);
	logprintf(0,"    Login max attempts msg: \"%s\"\n",login_max_attempts_msg);
	logprintf(0,"    Login max attempts    : %d\n",login_max_attempts);
	logprintf(0,"    Login timeout message : \"%s\"\n",login_timeout_msg);
	logprintf(0,"    Login timeout         : %d secs\n",login_timeout_secs);
	logprintf(0,"    Login pause           : %d secs\n",login_pause_secs);
	logprintf(0,"    Banned users          : ");
	if (banned_users_cnt)
	{
		for(i=0;i < banned_users_cnt;++i)
		{
			if (i) logprintf(0,", ");
			logprintf(0,"%s",banned_users[i]);
		}
		logprintf(0,"\n");
	}
	else logprintf(0,"<none>\n");
	logprintf(0,"    Banned user message   : \"%s\"\n",banned_user_msg);
	logprintf(0,"    Banned IPs (%slist): ",
		iplist_type == IP_BLACKLIST ? "black" : "white");
	if (iplist_cnt)
	{
		for(i=0;i < iplist_cnt;++i)
		{
			if (i) logprintf(0,", ");
			logprintf(0,"%s",iplist[i]);
		}
		logprintf(0,"\n");
	}
	else logprintf(0,"<none>\n");

	logprintf(0,"    Banned IP message     : ");
	if (banned_ip_msg)
		logprintf(0,"\"%s\"\n",banned_ip_msg);
	else
		logprintf(0,NOTSET);
	logprintf(0,"\n");
}
