#include "globals.h"

void processConfigParam(char *prm, char *value, int linenum);
#ifndef __APPLE__
void parseBannedUsers(char *list);
#endif
void parseInterface(char *addr);


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

	puts("Parsing config file...");

	if ((fd=open(config_file,O_RDWR,0666)) == -1)
	{
		perror("ERROR: parseConfigFile(): open()");
		exit(1);
	}
	if (fstat(fd,&fs) == -1)
	{
		perror("ERROR: parseConfigFile(): fstat()");
		exit(1);
	}
	if ((map_start = (char *)mmap(NULL,
		fs.st_size+1,
		PROT_READ | PROT_WRITE,MAP_PRIVATE,fd,0)) == MAP_FAILED)
	{
		perror("ERROR: parseConfigFile(): mmap()");
		exit(1);
	}
	close(fd);

	map_end = map_start + fs.st_size;
	linenum = 1;
	seek_nl = 0;

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
				fprintf(stderr,"ERROR: Missing quotes with parameter \"%s\" on line %d.\n",
					words[0],linenum);
				exit(1);
			case 0:
				break;
			case 2:
				processConfigParam(words[0],words[1],linenum);
				break;
			default:
				fprintf(stderr,"ERROR: Too %s arguments for parameter \"%s\" on line %d.\n",
					word_cnt > 2 ? "many" : "few",
					words[0],linenum);
				exit(1);
			}
			freeWords(words,word_cnt);
		}
		else ++ptr;
	}
	munmap(map_start,fs.st_size+1);

	if (!login_prompt) login_prompt = LOGIN_PROMPT;
	if (!pwd_prompt) pwd_prompt = PWD_PROMPT;
}




void processConfigParam(char *prm, char *value, int linenum)
{
	const char *param[] =
	{
		/* Flags */
		"be_daemon",
		"hexdump",
		"login_append_user",

		/* Numeric values */
		"port",
		"telopt_timeout_secs",
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
		"log_file"
	};
	enum
	{
		PAR_BE_DAEMON,
		PAR_HEXDUMP,
		PAR_LOGIN_APPEND_USER,

		PAR_PORT,
		PAR_TELOPT_TIMEOUT_SECS,
		PAR_LOGIN_MAX_ATTEMPTS,
		PAR_LOGIN_TIMEOUT_SECS,
		PAR_LOGIN_PAUSE_SECS,

		PAR_NETWORK_INTERFACE,
		PAR_LOGIN_PROGRAM,
		PAR_LOGIN_PROMPT,
		PAR_PWD_PROMPT,
		PAR_SHELL_PROGRAM,
		PAR_BANNED_USERS,
		PAR_MOTD_FILE,
		PAR_LOG_FILE,

		NUM_PARAMS
	};
	int is_num;
	int ivalue;
	int exec_cnt;
	int i;
	char *ptr;

	printf("   Line %-2d: \"%s\": ",linenum,prm);
	fflush(stdout);

	for(ptr=value;*ptr && isdigit(*ptr);++ptr);
	if (*ptr) is_num = 0;
	else
	{
		is_num = 1;
		ivalue = atoi(value);
	}
	exec_cnt = 0;

	for(i=0;i < NUM_PARAMS;++i)
	{
		if (strcmp(prm,param[i])) continue;

		switch(i)
		{
		/* Flags */
		case PAR_BE_DAEMON:
			if (!strcasecmp(value,"YES")) flags |= FLAG_DAEMON;
			else if (strcasecmp(value,"NO")) goto VAL_ERROR;
			break;
		case PAR_HEXDUMP:
			if (!strcasecmp(value,"YES")) flags |= FLAG_HEXDUMP;
			else if (strcasecmp(value,"NO")) goto VAL_ERROR;
			break;
		case PAR_LOGIN_APPEND_USER:
			if (!strcasecmp(value,"YES")) flags |= FLAG_APPEND_USER;
			else if (strcasecmp(value,"NO")) goto VAL_ERROR;
			break;

		/* Numeric values */
		case PAR_PORT:
			if (!is_num || ivalue < 1 || ivalue > 0xFFFF)
				goto VAL_ERROR;
			port = ivalue;
			break;
		case PAR_TELOPT_TIMEOUT_SECS:
			if (!is_num || ivalue < 0) goto VAL_ERROR;
			telopt_timeout_secs = ivalue;
			break;
		case PAR_LOGIN_MAX_ATTEMPTS:
#ifdef __APPLE__
		case PAR_LOGIN_TIMEOUT_SECS:
		case PAR_LOGIN_PAUSE_SECS:
			goto UNSUPPORTED;
#else
			if (!is_num || ivalue < 1) goto VAL_ERROR;
			login_max_attempts = ivalue;
			break;
		case PAR_LOGIN_TIMEOUT_SECS:
			if (!is_num || ivalue < 1) goto VAL_ERROR;
			login_timeout_secs = ivalue;
			break;
		case PAR_LOGIN_PAUSE_SECS:
			if (!is_num || ivalue < 0) goto VAL_ERROR;
			login_pause_secs = ivalue;
			break;
#endif
		/* String values */
		case PAR_NETWORK_INTERFACE:
			parseInterface(value);
			break;
		case PAR_LOGIN_PROGRAM:
			if (shell_exec_argv) goto EXCL_ERROR;
			if (login_exec_argv) goto ALREADY_SET_ERROR;
			splitString(
				value,
				NULL,&login_exec_argv,&login_exec_argv_cnt);
			if (login_exec_argv_cnt < 1)
			{
				fprintf(stderr,"ERROR: Empty or invalid login_program string on line %d.\n",linenum);
				exit(1);
			}
			break;
		case PAR_LOGIN_PROMPT:
#ifdef __APPLE__
		case PAR_PWD_PROMPT:
		case PAR_SHELL_PROGRAM:
		case PAR_BANNED_USERS:
			goto UNSUPPORTED;
#else
			if (login_prompt) goto ALREADY_SET_ERROR;
			login_prompt = strdup(value);
			break;
		case PAR_PWD_PROMPT:
			if (pwd_prompt) goto ALREADY_SET_ERROR;
			pwd_prompt = strdup(value);
			break;
		case PAR_SHELL_PROGRAM:
			if (login_exec_argv) goto EXCL_ERROR;
			if (shell_exec_argv) goto ALREADY_SET_ERROR;
			splitString(value,NULL,&shell_exec_argv,&exec_cnt);
			if (exec_cnt < 1)
			{
				fprintf(stderr,"ERROR: Empty or invalid shell_program string on line %d.\n",linenum);
				exit(1);
			}
			break;
		case PAR_BANNED_USERS:
			if (banned_users) goto ALREADY_SET_ERROR;
			parseBannedUsers(value);
			break;
#endif
		case PAR_MOTD_FILE:
			if (motd_file) goto ALREADY_SET_ERROR;
			motd_file = strdup(value);
			break;
		case PAR_LOG_FILE:
			if (log_file) goto ALREADY_SET_ERROR;
			log_file = strdup(value);
			break;
		default:
			assert(0);
		}
		puts("OK");
		return;
	}
	if (i == NUM_PARAMS)
	{
		fprintf(stderr,"ERROR: Unknown parameter.\n");
		exit(1);
	}

	VAL_ERROR:
	fprintf(stderr,"ERROR: Invalid value \"%s\".\n",value);
	exit(1);

	ALREADY_SET_ERROR:
	fprintf(stderr,"ERROR: Parameter already set.\n");
	exit(1);

	EXCL_ERROR:
	fputs("ERROR: The shell_program and login_program config file parameters are mutually exclusive.\n",stderr);
	exit(1);

#ifdef __APPLE__
	UNSUPPORTED:
	puts("WARNING: Not supported in this build.");
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

	iface = addr;
	if (getifaddrs(&addr_list) == -1)
	{
		perror("ERROR: parseInterface(): getifaddrs()");
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
	fprintf(stderr,"ERROR: Interface \"%s\" does not exist or is not IP4.\n",iface);
	exit(1);
}
