/*** For when telnetd does its own login validation ***/
#include "globals.h"

static struct stat fs;
static char *map_start;
static char *map_end;

int validateTelnetdPwd(char *password);
int mapTelnetdPwdFile();
int parseTelnetdPwdFile(char *password);
char *findEndOfPwd(char *ptr);

/*** Validate the user password. 1 means valid, 0 means invalid, -1 means
     some kind of fatal error ***/
int validatePwd(char *password)
{
#ifndef __APPLE__
	struct spwd *spwd;
	char *pwd;
	char *salt;
	char *hash;
	char *cry;
	int len;
#else
	/* If its not set for MacOS something's gone tits up in config.c */
	assert(pwd_file);
#endif
	/* Check user exists */
	if (!(userinfo = getpwnam(username))) return 0;
	if (pwd_file) return validateTelnetdPwd(password);
#ifndef __APPLE__
	/* If no password then get info from shadow password file */
	if (!strcmp(userinfo->pw_passwd,"x"))
	{
		if (!(spwd = getspnam(userinfo->pw_name)))
		{
			sockprintf("ERROR: validatePwd(): getspnam(): %s\n",strerror(errno));
			return -1;
		}
		pwd = spwd->sp_pwdp;
	}
	else pwd = userinfo->pw_passwd;

	/* If we have a '.' in the hash thats the delimiter between the salt
	   and the password hash, else look for the last '$' else just use the 
	   1st 2 characters for the salt */
	if ((hash = strchr(pwd,'.')) || (hash = strrchr(pwd,'$')))
	{
		len = (int)(hash - pwd);
		asprintf(&salt,"%.*s",len,pwd);
		++hash;
	}
	else
	{
		asprintf(&salt,"%.2s",pwd);
		hash = pwd + 2;
	}
	if (!(cry = crypt(password,salt)))
		logprintf(master_pid,"ERROR: validatePwd(): crypt() returned NULL");
	free(salt);
	return (cry ? !strcmp(cry,pwd) : 0);
#endif
	/* Prevents compiler warning in MacOS */
	return 0;
}




/*** Validate the user from the telnetd password file. Could have the file
     permanently mapped to save re-opening it all the time but that wouldn't
     see updates and it would be a security risk anyway ***/
int validateTelnetdPwd(char *password)
{
	int ret;

	assert(password);
	if (!*password) return 0;

	if (!mapTelnetdPwdFile()) return -1;
	ret = parseTelnetdPwdFile(password);

	munmap(map_start,fs.st_size);
	return ret;
}




/*** Map the file instead of reading it in 1 char at a time as its easier
     parsing it with pointers ***/
int mapTelnetdPwdFile()
{
	int fd;

	if ((fd=open(pwd_file,O_RDONLY,0666)) == -1)
	{
		logprintf(master_pid,"ERROR: mapTelnetdPwdFile(): open(): %s\n",
			strerror(errno));
		return 0;
	}
	if (fstat(fd,&fs) == -1)
	{
		logprintf(master_pid,"ERROR: mapTelnetdPwdFile(): fstat(): %s\n",
			strerror(errno));
		return 0;
	}
	/* size+1 so we can temporarily shove a \0 on end */
	if ((map_start = (char *)mmap(
		NULL,fs.st_size+1,
		PROT_READ | PROT_WRITE,MAP_PRIVATE,fd,0)) == MAP_FAILED)
	{
		logprintf(master_pid,"ERROR: mapTelnetdPwdFile(): mmap(): %s\n",
			strerror(errno));
		return 0;
	}
	close(fd);

	map_end = map_start + fs.st_size;
	return 1;
}




/*** Go through the file and find the user which is in global 'username' ***/
int parseTelnetdPwdFile(char *password)
{
	char *ptr;
	char *colon;
	char *end;
	char *salt;
	char *epwd;
	char c;
	int linenum;

	/* Parse the file */
	for(ptr=map_start,linenum=1;ptr < map_end;++ptr,++linenum)
	{
		/* Find start of line */
		for(;*ptr == '\n' && ptr < map_end;++ptr,++linenum);
		if (ptr == map_end) break;

		/* Manually added comments are allowed in the file */
		if (*ptr == '#') 
		{
			ptr = findEndOfPwd(ptr+1);
			continue;
		}

		/* Find colon seperator */
		for(colon=ptr;
		    *colon != ':' && *colon != '\n' && colon < map_end;++colon);
		if (*colon != ':')
		{
			logprintf(master_pid,"WARNING: parseTelnetdPwd(): Line %d corrupted in \"%s\".\n",
				linenum,pwd_file);
			ptr = findEndOfPwd(colon);
			continue;
		}
		*colon = 0;
		if (!strcmp(username,ptr)) goto FOUND_USER;
		ptr = findEndOfPwd(colon+1);
	}
	return 0;

	FOUND_USER:
	epwd = colon + 1;
	end = findEndOfPwd(epwd);
	*end = 0;

	/* Sanity check */
	if (strlen(epwd) < 4) return 0;

	/* If the encrypted password has '$' at start then its one of the
	   extended encryption types supported by glibc which are:
	      No $ = DES
	      $1$  = MD5
	      $2a$ = BLOWFISH (not in standard glibc)
	      $5$  = SHA256
	      $6$  = SHA512
	*/
	c = epwd[1];
	if (epwd[0] == '$' && isdigit(c) && (epwd[2] == '$' || epwd[3] == '$'))
	{
#ifdef __APPLE__
		/* Have to flag this because MacOS crypt() will happily try
		   and decrypt a non DES encryption because the dollar chars 
		   have no special meaning for it */
		logprintf(master_pid,"ERROR: parseTelnetdPwd(): Only DES encryption is supported by MacOS crypt() on line %d in \"%s\"\n",
			linenum,pwd_file);
		return -1;
#endif
		assert(asprintf(&salt,"$%c$%.2s$",c,username) != -1);
	}
	else assert(asprintf(&salt,"%.2s",username) != -1);

	if (!(ptr = crypt(password,salt)))
	{
		if (epwd[2] == '$')
			logprintf(master_pid,"ERROR: parseTelnetdPwd(): crypt() returned NULL. Possibly encryption type \"%c\" not supported.\n",c);
		else
			logprintf(master_pid,"ERROR: parseTelnetdPwd(): crypt() returned NULL. Possibly encryption type \"%c%c\" not supported.\n",c,epwd[2]);
	}
	free(salt);

	return ptr ? (!strcmp(ptr,epwd)) : -1;
}




/*** Also look for colon as in the future I might add further fields ***/
char *findEndOfPwd(char *ptr)
{
	for(;*ptr != '\n' && *ptr != ':' && ptr < map_end;++ptr);
	return ptr;
}
