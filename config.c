#include "globals.h"

#define CHECK_STR_PARAM(P) \
	if (P) \
	{ \
		if (flags.sighup) \
			free(P); \
		else \
			goto ALREADY_SET_ERROR; \
	}


void processConfigParam(char *param, char *value, int linenum);
#ifndef __APPLE__
void parseBannedUsers(char *list);
#endif
void parseInterface(char *addr);
void printParams();
void freeArray(char **words, int word_cnt);


/*** If the config file is bad parseConfigFile() or processConfigParam() will 
     terminate the process even if we're re-reading via SIGHUP as rescuing the
     system from a partially parsed config is a lot of hassle involving temp 
     config variables. logprintf(0,... because only the parent process runs
     the following functions and we don't want the preamble printed in the
     boot up messages or when reparsing the config. */
void parseConfigFile()
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

	logprintf(0,">>> Parsing config file...\n");

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
	if (flags.sighup)
	{
		if (shell_exec_argv)
		{
			freeArray(shell_exec_argv,shell_exec_argv_cnt);
			shell_exec_argv = NULL;
			shell_exec_argv_cnt = 0;
		}
		if (login_exec_argv)
		{
			freeArray(login_exec_argv,login_exec_argv_cnt);
			login_exec_argv = NULL;
			login_exec_argv_cnt = 0;
		}
		if (banned_users)
		{
			freeArray(banned_users,banned_users_cnt);
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
			case 2:
				processConfigParam(words[0],words[1],linenum);
				break;
			default:
				logprintf(0,"ERROR: Too %s arguments for parameter \"%s\" on line %d.\n",
					word_cnt > 2 ? "many" : "few",
					words[0],linenum);
				parentExit(-1);
			}
			freeArray(words,word_cnt);
		}
		else ++ptr;
	}
	munmap(map_start,fs.st_size+1);

	if (!login_prompt) login_prompt = LOGIN_PROMPT;
	if (!pwd_prompt) pwd_prompt = PWD_PROMPT;

	printParams();
}




void processConfigParam(char *param, char *value, int linenum)
{
	const char *params[] =
	{
		/* Flags */
		"be_daemon",
		"hexdump",
		"login_append_user",
		"login_preserve_env",

		/* Numeric values */
		"port",
		"telopt_timeout_secs",
		"log_file_max_fails",
		"login_max_attempts",
		"login_timeout_secs",
		"login_pause_secs",

		/* String values */
		"network_interface",
		"login_program",
		"login_prompt",
		"pwd_prompt",
		"shell_program",
		"banned_users",
		"motd_file",
		"log_file",
		"log_file_rm"
	};
	enum
	{
		PARAM_BE_DAEMON,
		PARAM_HEXDUMP,
		PARAM_LOGIN_APPEND_USER,
		PARAM_LOGIN_PRESERVE_ENV,

		PARAM_PORT,
		PARAM_TELOPT_TIMEOUT_SECS,
		PARAM_LOG_FILE_MAX_FAILS,
		PARAM_LOGIN_MAX_ATTEMPTS,
		PARAM_LOGIN_TIMEOUT_SECS,
		PARAM_LOGIN_PAUSE_SECS,

		PARAM_NETWORK_INTERFACE,
		PARAM_LOGIN_PROGRAM,
		PARAM_LOGIN_PROMPT,
		PARAM_PWD_PROMPT,
		PARAM_SHELL_PROGRAM,
		PARAM_BANNED_USERS,
		PARAM_MOTD_FILE,
		PARAM_LOG_FILE,
		PARAM_LOG_FILE_RM,

		NUM_PARAMS
	};
	int is_num;
	int ivalue;
	int yes;
	int i;
	char *ptr;

	logprintf(0,"    Line %-2d: \"%s\": ",linenum,param);

	/* Check for numeric value */
	for(ptr=value;*ptr && isdigit(*ptr);++ptr);
	if (*ptr) is_num = 0;
	else
	{
		is_num = 1;
		ivalue = atoi(value);
	}
	shell_exec_argv_cnt = 0;

	for(i=0;i < NUM_PARAMS;++i)
	{
		if (strcmp(param,params[i])) continue;
		if (is_num) yes = -1;
		else if (!strcasecmp(value,"YES") || !strcasecmp(value,"TRUE"))
			yes = 1;
		else if (!strcasecmp(value,"NO") || !strcasecmp(value,"FALSE"))
			yes = 0;
		else yes = -1;

		switch(i)
		{
		/* Flags */
		case PARAM_BE_DAEMON:
			if (flags.sighup) goto IGNORE_WARNING; /* Too late */
			if (yes == -1) goto VAL_ERROR;
			flags.daemon = yes;
			break;
		case PARAM_HEXDUMP:
			if (yes == -1) goto VAL_ERROR;
			flags.hexdump = yes;
			break;
		case PARAM_LOGIN_APPEND_USER:
			if (yes == -1) goto VAL_ERROR;
			flags.append_user = yes;
			break;
		case PARAM_LOGIN_PRESERVE_ENV:
			if (yes == -1) goto VAL_ERROR;
			flags.preserve_env = yes;
			break;

		/* Numeric values */
		case PARAM_PORT:
			/* Ignore if SIGHUP as it would mean closing the
			   current socket and re-creating. Too much hassle. */
			if (flags.sighup) goto IGNORE_WARNING;
			if (!is_num || ivalue < 1 || ivalue > 0xFFFF)
				goto VAL_ERROR;
			port = ivalue;
			break;
		case PARAM_TELOPT_TIMEOUT_SECS:
			if (!is_num || ivalue < 0) goto VAL_ERROR;
			telopt_timeout_secs = ivalue;
			break;
		case PARAM_LOG_FILE_MAX_FAILS:
			if (!is_num || ivalue < 0) goto VAL_ERROR;
			if (flags.log_fails_override) goto OVERRIDE;
			log_file_max_fails = ivalue;
			break;
#ifdef __APPLE__
		case PARAM_LOGIN_MAX_ATTEMPTS:
		case PARAM_LOGIN_TIMEOUT_SECS:
		case PARAM_LOGIN_PAUSE_SECS:
			goto UNSUPPORTED;
#else
		case PARAM_LOGIN_MAX_ATTEMPTS:
			if (!is_num || ivalue < 1) goto VAL_ERROR;
			login_max_attempts = ivalue;
			break;
		case PARAM_LOGIN_TIMEOUT_SECS:
			if (!is_num || ivalue < 1) goto VAL_ERROR;
			login_timeout_secs = ivalue;
			break;
		case PARAM_LOGIN_PAUSE_SECS:
			if (!is_num || ivalue < 0) goto VAL_ERROR;
			login_pause_secs = ivalue;
			break;
#endif
		/* String values */
		case PARAM_NETWORK_INTERFACE:
			if (flags.sighup) goto IGNORE_WARNING;
			parseInterface(value);
			break;
		case PARAM_LOGIN_PROGRAM:
			if (shell_exec_argv) goto EXCL_ERROR;
			if (login_exec_argv) goto ALREADY_SET_ERROR;
			splitString(
				value,
				NULL,&login_exec_argv,&login_exec_argv_cnt);
			if (login_exec_argv_cnt < 1)
			{
				logprintf(0,"ERROR: Empty or invalid login_program string on line %d.\n",linenum);
				parentExit(-1);
			}
			break;
#ifdef __APPLE__
		case PARAM_LOGIN_PROMPT:
		case PARAM_PWD_PROMPT:
		case PARAM_SHELL_PROGRAM:
		case PARAM_BANNED_USERS:
			goto UNSUPPORTED;
#else
		case PARAM_LOGIN_PROMPT:
			CHECK_STR_PARAM(login_prompt);
			login_prompt = strdup(value);
			break;
		case PARAM_PWD_PROMPT:
			CHECK_STR_PARAM(pwd_prompt);
			pwd_prompt = strdup(value);
			break;
		case PARAM_SHELL_PROGRAM:
			if (login_exec_argv) goto EXCL_ERROR;
			if (shell_exec_argv) goto ALREADY_SET_ERROR;
			splitString(
				value,NULL,
				&shell_exec_argv,&shell_exec_argv_cnt);
			if (shell_exec_argv_cnt < 1)
			{
				logprintf(0,"ERROR: Empty or invalid shell_program string on line %d.\n",linenum);
				parentExit(-1);
			}
			break;
		case PARAM_BANNED_USERS:
			if (banned_users) goto ALREADY_SET_ERROR;
			parseBannedUsers(value);
			break;
#endif
		case PARAM_MOTD_FILE:
			CHECK_STR_PARAM(motd_file);
			motd_file = strdup(value);
			break;
		case PARAM_LOG_FILE:
		case PARAM_LOG_FILE_RM:
			if (flags.sighup) goto IGNORE_WARNING;
			if (flags.log_file_override) goto OVERRIDE;

			/* Print OK before setting the log file or at startup 
			   we'll have the "Line" number on stdout and the OK
			   in the log file */
			logprintf(0,"OK\n");
			logprintf(0,">>> Redirecting output to \"%s\"...\n",value);
			log_file = strdup(value);
			if (i == PARAM_LOG_FILE_RM) unlink(log_file);
			return;
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
	logprintf(0,"ERROR: Parameter already set.\n");
	parentExit(-1);

	EXCL_ERROR:
	logprintf(0,"ERROR: The shell_program and login_program config file parameters are mutually exclusive.\n");
	parentExit(-1);

	IGNORE_WARNING:
	logprintf(0,"WARNING: Parameter \"%s\" ignored - valid at startup only.\n",param);
	return;
	
	OVERRIDE:
	logprintf(0,"WARNING: Parameter \"%s\" overridden by command line argument.\n",param);
	return;

#ifdef __APPLE__
	UNSUPPORTED:
	logprintf(0,"WARNING: Not supported in a MacOS build.\n");
	return;
#endif
}



#ifndef __APPLE__
void parseBannedUsers(char *list)
{
	char *user;

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
#endif



void parseInterface(char *addr)
{
	struct ifaddrs *addr_list;
	struct ifaddrs *entry;

	/* Valid IP address or interface name? */
	if ((iface_in_addr.sin_addr.s_addr = inet_addr(addr)) != -1) return;

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



#define NOTSET    "<not set>\n"
#define PRTSTR(S) (S ? S : "<not set>")

void printParams()
{
#ifndef __APPLE__
	char **ptr;
#endif
	int i;

	/* Don't need parent id as we're doing short log lines */
	logprintf(0,"\n    Parameter           Value\n");
	logprintf(0,"    ---------           -----\n");
	logprintf(0,"    Config file       : %s\n",PRTSTR(config_file));
	logprintf(0,"    MOTD file         : %s\n",PRTSTR(motd_file));
	logprintf(0,"    Log file          : %s\n",PRTSTR(log_file));
	logprintf(0,"    Log file max fails: %d\n",log_file_max_fails);
	logprintf(0,"    Network interface : %s\n",PRTSTR(iface));
	logprintf(0,"    Port              : %d\n",port);
	logprintf(0,"    Telopt timeout    : %d secs\n",telopt_timeout_secs);
	logprintf(0,"    Be daemon         : %s\n",flags.daemon ? "YES" : "NO");
	logprintf(0,"    Hexdump           : %s\n",flags.hexdump ? "YES" : "NO");
	logprintf(0,"    Login append user : %s\n",flags.append_user ? "YES" : "NO");
	logprintf(0,"    Login preserve env: %s\n",flags.preserve_env ? "YES" : "NO");
#ifndef __APPLE__
	logprintf(0,"    Login max attempts: %d\n",login_max_attempts);
	logprintf(0,"    Login timeout     : %d secs\n",login_timeout_secs);
	logprintf(0,"    Login pause       : %d secs\n",login_pause_secs);
	logprintf(0,"    Login prompt      : ");
	if (login_prompt)
		logprintf(0,"\"%s\"\n",login_prompt);
	else
		logprintf(0,NOTSET);
	logprintf(0,"    Password prompt   : ");
	if (pwd_prompt)
		logprintf(0,"\"%s\"\n",pwd_prompt);
	else
		logprintf(0,NOTSET);
	logprintf(0,"    Banned users      : ");
	if (banned_users_cnt)
	{
		for(i=0;i < banned_users_cnt;++i)
		{
			if (i) logprintf(0,",");
			logprintf(0,"%s",banned_users[i]);
		}
		logprintf(0,"\n");
	}
	else logprintf(0,"<none>\n");
#endif
	logprintf(0,"    Login process args: ");
	if (login_exec_argv_cnt)
	{
                for(i=0;i < login_exec_argv_cnt;++i)
		{
			if (i) logprintf(0,",");
			logprintf(0,"%s",login_exec_argv[i]);
		}
		if (flags.append_user)
			logprintf(0,",[TELNET USER]\n");
		else
			logprintf(0,"\n");
	}
	else if (shell_exec_argv) logprintf(0,NOTSET);
	else
	{
		logprintf(0,"%s%s%s\n",
			LOGIN_PROG,
			flags.preserve_env ? ",-p" : "",
			flags.append_user ? ",[TELNET USER]" : "");
	}
#ifndef __APPLE__
	logprintf(0,"    Shell process args: ");
	if (shell_exec_argv)
	{
                for(ptr=shell_exec_argv;*ptr;++ptr)
		{
			if (ptr != shell_exec_argv) logprintf(0,",");
			logprintf(0,"%s",*ptr);
		}
		logprintf(0,"\n");
	}
	else logprintf(0,NOTSET);
#endif
	logprintf(0,"\n");
}




void freeArray(char **array, int entry_cnt)
{
	int i;
	for(i=0;i < entry_cnt;++i) free(array[i]);
	free(array);
}
