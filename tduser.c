/*****************************************************************************
 TDUSER
 Adds a user to telnetd's password file which is an alternative to the system
 login and also will converted old password format files (pre telnetd version 
 20240906) to the current one. Password line format is now:

 <username>:<encrypted pwd>:<max attempts>:<reserved>:<shell string>
 *****************************************************************************/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <termios.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "build_date.h"

#define VERSION       "20240906"
#define FILENAME      "telnetd.pwd"
#define MIN_USER_LEN  2
#define MAX_USER_LEN  32 /* Seems to be a general unix limit */
#define MIN_PWD_LEN   3  
#define MAX_PWD_LEN   255 /* Ditto above */

#define STDIN         0
#define STDOUT        1
#define ESCAPE        27
#define BACKSPACE     127

enum
{
	ENC_DES,
	ENC_MD5,
	ENC_SHA256,
	ENC_SHA512,
	ENC_BLOWFISH,

	NUM_ENC_METHODS
} enc_type;

char *enc_name[NUM_ENC_METHODS] =
{
	"DES",
	"MD5",
	"SHA256",
	"SHA512",
	"BLOWFISH"
};

#ifndef __APPLE__
char *enc_code[NUM_ENC_METHODS] =
{
	"",
	"$1$",
	"$5$",
	"$6$",
	"$2a$"
};
#endif

struct stat fs;
struct termios saved_tio;
char *username;
char *password;
char *filename;
char *shell_str;
char *map_start;
char *map_end;
int kbraw;
int attempts;
int convert;

void  init(void);
void  parseConfigFile(int argc, char **argv);
void  version(void);
void  listSupported(void);
char *getString(int pwd);
void  getUsername(void);
void  getPassword(void);
void  checkValidUsername(void);
void  mapFile(void);
void  convertFile(void);
void  checkNewUser(void);
void  writeEntry(void);
void  sigHandler(int sig);


int main(int argc, char **argv)
{
	init();
	parseConfigFile(argc,argv);
	if (convert)
	{
		mapFile();
		convertFile();
		return 0;
	}
	if (!username) getUsername();
	if (!password) getPassword();
	checkValidUsername();

	/* Only parse file if it exists */
	if (!access(filename,F_OK))
	{
		mapFile();
		checkNewUser();
	}
	writeEntry();
	return 0;
}




void init(void)
{
	signal(SIGINT,sigHandler);
	signal(SIGQUIT,sigHandler);
	kbraw = 0;
}




void parseConfigFile(int argc, char **argv)
{
	int i;
	char c;

	username = NULL;
	password = NULL;
	shell_str = NULL;
	filename = NULL;
	enc_type = ENC_DES;
	attempts = 0;
	convert = 0;

	for(i=1;i < argc;++i)
	{
		if (argv[i][0] != '-' || strlen(argv[i]) != 2)
			goto USAGE;


		c = argv[i][1];
		switch(c)
		{
		case 'c':
			convert = 1;
			continue;
#ifndef __APPLE__
		case 'l':
			listSupported();
			continue;
#endif
		case 'v':
			version();
		}

		if (i == argc - 1) goto USAGE;

		switch(argv[i][1])
		{
		case 'u':
			username = argv[++i];
			break;
		case 'p':
			password = argv[++i];
			break;
		case 'f':
			filename = argv[++i];
			break;
		case 'm':
			attempts = atoi(argv[++i]);
			break;
		case 's':
			shell_str = argv[++i];
			break;
#ifndef __APPLE__
		/* MacOS crypt() is limited to DES wheres glib crypt() is far 
		   more powerful */
		case 'e':
			++i;
			for(enc_type=0;
			    enc_type < NUM_ENC_METHODS && strcasecmp(argv[i],enc_name[enc_type]);
			    ++enc_type);
			if (enc_type == NUM_ENC_METHODS) goto USAGE;
			break;	
#endif
		default:
			goto USAGE;
		}
	}
	if (!filename) filename = FILENAME;
	if (attempts >= 0) return;

	USAGE:
	printf("Usage: %s\n"
	       "       -u <username>\n"
	       "       -p <password>\n"
	       "       -s <exec string>        : User shell program and args. This overrides the\n"
	       "                                 default system wide field in telnetd.cfg.\n"
	       "                                 Default = none\n"
	       "       -f <password file>      : Default = \"%s\"\n"
	       "       -m <max login attempts> : Max login attempts for user at login prompt.\n"
	       "                                 Must be >= 0. Zero means user system default.\n"
	       "                                 Default = 0.\n"
#ifndef __APPLE__
	       "       -e <encryption type>    : Options are DES,MD5,SHA256,SHA512 and BFISH.\n"
	       "                                 Default = DES\n"
	       "       -l                      : List supported encryption types then exit.\n"
#endif
	       "       -c                      : Convert an old format password file into the\n"
	       "                                 new format and write it to stdout.\n"
	       "       -v                      : Print version and build date then exit.\n"
	       "\nNote: All arguments are optional. If username and/or password are not provided\n"
	       "      you will be prompted for them unless -c given. This means they will not\n"
	       "      get stored in the shell history as they would using the command line\n"
	       "      arguments. The -c option only uses -f and -m.\n",
		argv[0],FILENAME);
	exit(1);
}




void version(void)
{
	puts("\n*** TDUSER ***\n");
	printf("Version   : %s\n",VERSION);
	printf("Build     : ");
#ifdef __APPLE__
	printf("MacOS\n");
#else
	printf("Linux/generic\n");
#endif
	printf("Build date: %s\n\n",BUILD_DATE);
	exit(0);
}




#ifndef __APPLE__
/*** Show which encryption functions we support ***/
void listSupported()
{
	char salt[7];
	char *ptr;
	int i;

	puts("Supported by crypt() on this system:");
	for(i=0;i < NUM_ENC_METHODS;++i)
	{
		sprintf(salt,"%sab",enc_code[i]);
		ptr = crypt("x",salt);
		printf("    %-8s: %s\n",
			enc_name[i],
			(!ptr || (i == ENC_BLOWFISH && ptr[3] != '$')) ? "NO" : "YES");
	}
	exit(0);
}
#endif




void rawMode(void)
{
	struct termios tio;

	/* Get current settings */
	tcgetattr(0,&tio);
	tcgetattr(0,&saved_tio);

	/* Echo off */
	tio.c_lflag &= ~ECHO;

	/* Disable canonical mode */
	tio.c_lflag &= ~ICANON;

	/* Don't strip off 8th bit */
	tio.c_iflag &= ~ISTRIP;

	/* Set buffer size to 1 byte and no delay between reads */
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;

	tcsetattr(0,TCSANOW,&tio);
	kbraw = 1;

}




void cookedMode(void)
{
	if (kbraw)
	{
		tcsetattr(0,TCSANOW,&saved_tio);
		kbraw = 0;
	}
}




/*** This doesn't deal with the PC delete key which uses escape codes.
     Use backspace instead ***/
char *getString(int pwd)
{
	static char text[MAX_PWD_LEN+1];
	char key[4];
	u_char c;
	int maxlen;
	int rlen;
	int tlen;

	rawMode();
	maxlen = pwd ? MAX_PWD_LEN : MAX_USER_LEN;

	RESTART:
	write(STDOUT,pwd ? "Password: " : "Username: ",10);
	
	for(tlen=0;;)
	{
		/* The only reason to use this is to discard escape sequences
		   such as the delete key. Normal keys will only appear 1
		   char at a time */
		if ((rlen = read(STDIN,key,sizeof(key))) < 1) break;
		c = (u_char)key[0];
		if (c == ESCAPE || rlen != 1) continue;

		switch((char)c)
		{
		case EOF:
		case '\n':
			if (!tlen)
			{
				putchar('\n');
				goto RESTART;
			}
			goto DONE;
		case '\b':
		case BACKSPACE:
			if (tlen)
			{
				--tlen;
				write(STDOUT,"\b \b",3);
			}
			break;
		default:
			if (c > 31 && c < 127 && tlen < maxlen)
			{
				text[tlen++] = (char)c;
				if (pwd) c = '*';
				write(STDOUT,&c,1);
			}
		}
	}
	DONE:
	cookedMode();

	text[tlen] = 0;
	putchar('\n');
	return text;
}




void getUsername(void)
{
	username = strdup(getString(0));
}




void getPassword(void)
{
	password = strdup(getString(1));
}




/*** Trying to follow the standard rules for unix passwords. Ie start with
     a letter and the rest can only be letters, digits or the allowed 
     punctuation ***/
void checkValidUsername(void)
{
	char *n = username;
	int len = strlen(n);

	if (len < MIN_USER_LEN || len > MAX_USER_LEN)
	{
		fprintf(stderr,"ERROR: Usernames must be from %d to %d characters long.\n",MIN_USER_LEN,MAX_USER_LEN);
		exit(1);
	}
	if (!isalpha(*n))
	{
		fprintf(stderr,"ERROR: Usernames must start with a letter.\n");
		exit(1);
	}
	for(;*n;++n)
	{
		switch(*n)
		{
		case '-':
		case '.':
		case '_':
			/* Allowed */
			break;
		default:
			if (!isalpha(*n) && !isdigit(*n))
			{
				fprintf(stderr,"ERROR: Invalid character '%c' in username.\n",*n);
				exit(1);
			}
		}
	}

	/* Check if exists on system */
	if (!getpwnam(username))
	{
		fprintf(stderr,"WARNING: The user does not exist on this system and will not be able to log in\n");
		fprintf(stderr,"         through telnetd here.\n");
	}
}




/*** Simpler to search a file by pointer than reading in char by char ***/
void mapFile(void)
{
	int fd;

	if ((fd=open(filename,O_RDONLY,0666)) == -1)
	{
		perror("ERROR: open()");
		exit(1);
	}
	if (fstat(fd,&fs) == -1)
	{
		perror("ERROR: fstat()");
		exit(1);
	}
	if ((map_start = (char *)mmap(
		NULL,fs.st_size,
		PROT_READ | PROT_WRITE,MAP_PRIVATE,fd,0)) == MAP_FAILED)
	{
		perror("ERROR: mmap()");
		exit(1);
	}
	close(fd);

	map_end = map_start + fs.st_size;
}




/*** This converts from the old file format to the new one which it writes 
     to stdout ***/
void convertFile(void)
{
	char *ptr;
	char c;
	int colons = 0;
	int comment = 0;
	int line_start = 1;
	int linenum = 1;

	/* Old format: <username>:<encrypted pwd>:<shell string> 
	   New format: <username>:<encrypted pwd>:<max attempts>:<reserved>:<shell string>
	*/
	for(ptr=map_start;ptr < map_end;++ptr)
	{
		c = *ptr;
		switch(c)
		{
		case '#':
			putchar(c);
			if (line_start)
			{
				comment = 1;
				line_start = 0;
			}
			break;
		case '\n':
			if (!comment && colons == 1) printf(":%d::",attempts);
			putchar(c);
			++linenum;
			line_start = 1;
			comment = 0;
			colons = 0;
			break;
		case ':':
			putchar(c);
			if (!comment)	
			{
				if (++colons == 2) printf("%d::",attempts);
				else if (colons > 2)
				{
					fprintf(stderr,"ERROR: Too many colons on line %d. New format file?\n",linenum);
					exit(1);
				}
			}
			line_start = 0;
			break;
		default:
			putchar(c);
			if (!isspace(c)) line_start = 0;
		}
	}
}




/*** Get the user name (2nd field) and check it ***/
void checkNewUser(void)
{
	char *ptr;
	char *colon;
	int linenum;

	for(ptr=map_start,linenum=1;ptr < map_end;++ptr,++linenum)
	{
		/* Find start of line */
		for(;*ptr == '\n' && ptr < map_end;++ptr,++linenum);
		if (ptr == map_end) return;

		/* Comments can be manually added */
		colon = ptr;
		if (*ptr == '#') goto FIND_END;

		/* Find colon. Can't use strchr() as no null */
		for(colon=ptr;
		    *colon != ':' && *colon != '\n' && colon < map_end;
		    ++colon);
		if (*colon != ':')
		{
			fprintf(stderr,"WARNING: Line %d corrupted.\n",linenum);
			goto FIND_END;
		}
		*colon = 0;
		if (!strcmp(ptr,username))
		{
			fprintf(stderr,"ERROR: Username \"%s\" already present. Manually remove the entry then retry.\n",username);
			exit(1);
		}

		/* Find end of line */
		FIND_END:
		for(ptr=colon;*ptr != '\n' && ptr < map_end;++ptr);
	}

	/* Don't need the file to be mapped anymore */
	munmap(map_start,fs.st_size);
}




/*** Write the entry to the password file ***/
void writeEntry(void)
{
	FILE *fp;
	char *salt;
	char *ptr;
	int ret;

	if (enc_type == ENC_DES)
		assert(asprintf(&salt,"%.2s",username) != -1);
	else
#ifdef __APPLE__
		assert(0);
#else
		assert(asprintf(&salt,"%s%.2s$",enc_code[enc_type],username) != -1);
#endif
	/* If NULL with Linux the encryption type is not supported */
	ptr = crypt(password,salt);

	/* Blowfish sanity check - Blowfish can appear to work but actually 
	   doesn't. Can check by seeing if 2nd '$' is in output */
	if (!(ptr = crypt(password,salt)) || 
	     (enc_type == ENC_BLOWFISH && ptr[3] != '$'))
	{
		fprintf(stderr,"ERROR: crypt() failed. Encryption type probably not supported.\n");
		exit(1);
	}
	if (!(fp = fopen(filename,"a")))
	{
		perror("ERROR: fopen()");
		exit(1);
	}
	if (shell_str)
		ret = fprintf(fp,"%s:%s:%d::%s\n",username,ptr,attempts,shell_str);
	else
		ret = fprintf(fp,"%s:%s:%d::\n",username,ptr,attempts);

	fclose(fp);
	if (ret == -1)
	{
		perror("ERROR: fprintf()");
		exit(1);
	}

	printf("Username \"%s\" added to \"%s\" with %s encryption.\n",
		username,filename,enc_name[enc_type]);
}




void sigHandler(int sig)
{
	putchar('\n');
	cookedMode();
	exit(sig);
}
