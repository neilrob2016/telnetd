#define _XOPEN_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <termios.h>
#include <time.h>
#include <pwd.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <utmpx.h>
#ifndef __APPLE__
#include <shadow.h>
#include <crypt.h>
#endif
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>

#include "build_date.h"

#define SVR_NAME    "NRJ-TelnetD"
#define SVR_VERSION "20240906"

#define PORT                23
#define BUFFSIZE            2000
#define LOGIN_PAUSE_SECS    0
#define LOGIN_TIMEOUT_SECS  20
#define LOGIN_MAX_ATTEMPTS  3
#define TELOPT_TIMEOUT_SECS 2
#define LOG_FILE_MAX_FAILS  2
#define MAX_INTERFACES      256 /* Don't know system limit but can't be more */

#define FREE(M) if (M) free(M)

#ifdef __APPLE__
#define LOGIN_PROG "/usr/bin/login"
#else
#define LOGIN_PROG "/bin/login"
#endif

/* More useful macro names. Defined in arpa/telnet.h */
#define TELNET_SE   SE
#define TELNET_BRK  BREAK
#define TELNET_IP   IP
#define TELNET_AO   AO
#define TELNET_AYT  AYT
#define TELNET_EC   EC
#define TELNET_EL   EL
#define TELNET_GA   GA
#define TELNET_SB   SB
#define TELNET_WILL WILL
#define TELNET_WONT WONT
#define TELNET_DO   DO
#define TELNET_DONT DONT
#define TELNET_IAC  IAC

#ifndef MAINFILE
#define EXTERN extern
#else
#define EXTERN
#endif

enum
{
	STDIN,
	STDOUT,
	STDERR
};

enum
{
	STATE_NOTSET,

	STATE_TELOPT,
	STATE_LOGIN,
	STATE_PWD,
	STATE_PIPE,

	NUM_STATES
};

enum
{
	PWD_USER,
	PWD_EPWD,
	PWD_MAX_ATTEMPTS,
	PWD_RESERVED,
	PWD_EXEC_STR,

	NUM_PWD_FIELDS
};

enum
{
	IP_NO_LIST,
	IP_WHITELIST,
	IP_BLACKLIST
};


struct st_flags
{
	/* Config file flags */
	unsigned daemon             : 1;
	unsigned daemon_tmp         : 1;
	unsigned hexdump            : 1;
	unsigned append_user        : 1;
	unsigned preserve_env       : 1;
	unsigned log_file_override  : 1;
	unsigned log_fails_override : 1;
	unsigned pwd_asterisks      : 1;
	unsigned dns_lookup         : 1;
	unsigned store_host_in_utmp : 1;
	unsigned show_term_resize   : 1;
	unsigned ignore_sighup      : 1;
	unsigned version            : 1;

	/* Runtime */
	unsigned echo      : 1;
	unsigned rx_sighup : 1;
	unsigned rx_ttype  : 1;
	unsigned rx_env    : 1;
};


struct st_interface
{
	char *name;
	int sock;
	struct sockaddr_in addr;
};

EXTERN struct st_interface iface[MAX_INTERFACES];

/* Config file */
EXTERN char *config_file;
EXTERN char *login_prompt;
EXTERN char *pwd_prompt;
EXTERN char *pre_motd_file;
EXTERN char *post_motd_file;
EXTERN char *log_file;
EXTERN char *pwd_file;
EXTERN char **banned_users;
EXTERN char *banned_user_msg;
EXTERN char *banned_ip_msg;
EXTERN char **shell_exec_argv;
EXTERN char **login_exec_argv;
EXTERN char *login_incorrect_msg;
EXTERN char *login_max_attempts_msg;
EXTERN char *login_svrerr_msg;
EXTERN char *login_timeout_msg;
EXTERN char **iplist;
EXTERN int shell_exec_argv_cnt;
EXTERN int login_exec_argv_cnt;
EXTERN int login_max_attempts;
EXTERN int login_pause_secs;
EXTERN int login_timeout_secs;
EXTERN int banned_users_cnt;
EXTERN int telopt_timeout_secs;
EXTERN int log_file_max_fails;
EXTERN int port;
EXTERN int iplist_cnt;
EXTERN int iplist_type;
EXTERN int num_interfaces;

/* General */
EXTERN struct st_flags flags;
EXTERN pid_t parent_pid;
EXTERN u_char buff[BUFFSIZE+1];
EXTERN u_char line[BUFFSIZE+1];
EXTERN char username[BUFFSIZE+1];
EXTERN char ptybuff[BUFFSIZE+1];
EXTERN char ipaddrstr[20];
EXTERN char *dnsaddr;
EXTERN int log_file_fail_cnt;
EXTERN int term_height;
EXTERN int term_width;
EXTERN int buffpos;
EXTERN int sock;

/* Child */
EXTERN struct passwd *userinfo;
EXTERN sigset_t usr1_sigmask;
EXTERN pid_t master_pid;
EXTERN pid_t slave_pid;
EXTERN char *telopt_username;
EXTERN char prev_rx_c;
EXTERN int line_buffpos;
EXTERN int attempts;
EXTERN int state;
EXTERN int ptym;
EXTERN int ptys;

/* config.c */
void parseConfigFile(void);

/* master_child.c */
void runMaster(struct sockaddr_in *ip_addr);
void setUserNameAndPwdState(char *uname);
int  loginAllowed(char *uname);
void checkLoginAttempts(void);
void storeWinSize(void);
void masterExit(int code);

/* slave_child.c */
void runSlave(void);
void notifyWinSize(void);

/* pty.c */
int  openPTYMaster(void);
int  openPTYSlave(void);
char *getPTYName(void);

/* network.c */
void createListenSocket(int inum);
void readSock(void);
void writeSock(u_char *data, int len);

/* validate.c */
int validatePwd(char *password);

/* printf.c */
void sockprintf(char *fmt, ...);
void logprintf(pid_t pid, char *fmt, ...);

/* telopt.c */
void sendInitialTelopt(void);
u_char *parseTelopt(u_char *p, u_char *end);

/* split.c */
char *splitString(char *str, char *end, char ***words, int *word_cnt);
void  addWordToArray(char ***words, char *word, char *end, int *word_cnt);
void  freeWordArray(char **words, int word_cnt);
char *splitPwdLine(char *line, char *map_end, char **field);

/* iplist.c */
void addToIPList(char *addrstr);
int  authorisedIP(char *addrstr);

/* motd.c */
void sendMOTD(char *file);

/* misc.c */
void setState(int st);
void parsePath(char **path);
void parentExit(int code);
