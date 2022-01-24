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
#ifdef __APPLE__
#include <utmpx.h>
#else
#include <shadow.h>
#include <crypt.h>
#include <utmp.h>
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
#define SVR_VERSION "20220124"

#define PORT                23
#define BUFFSIZE            2000
#define LOGIN_PAUSE_SECS    0
#define LOGIN_TIMEOUT_SECS  20
#define LOGIN_MAX_ATTEMPTS  3
#define TELOPT_TIMEOUT_SECS 2

#ifdef __APPLE__
#define LOGIN_PROG     "/usr/bin/login"
#else
#define LOGIN_PROG     "/bin/login"
#endif
#define CONFIG_FILE    "telnetd.cfg"
#define LOGIN_PROMPT   "login: "
#define PWD_PROMPT     "password: "
#define HEXDUMP_CHARS  10
#define DELETE_KEY     127

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

#define IS_VAR_START(C) (C == NEW_ENV_VAR || C == ENV_USERVAR)

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
	STATE_SHELL,

	NUM_STATES
};

struct st_flags
{
	unsigned echo        : 1;
	unsigned daemon      : 1;
	unsigned hexdump     : 1;
	unsigned rx_ttype    : 1;
	unsigned rx_env      : 1;
	unsigned append_user : 1;
	unsigned preserve_env: 1;
};

/* Config file */
EXTERN char *iface;
EXTERN char *config_file;
EXTERN char *login_prompt;
EXTERN char *pwd_prompt;
EXTERN char *motd_file;
EXTERN char **banned_users;
EXTERN int login_max_attempts;
EXTERN int login_pause_secs;
EXTERN int login_timeout_secs;
EXTERN int banned_users_cnt;
EXTERN int telopt_timeout_secs;
EXTERN int port;

/* General */
EXTERN struct sockaddr_in iface_in_addr;
EXTERN struct st_flags flags;
EXTERN pid_t parent_pid;
EXTERN char username[BUFFSIZE+1];
EXTERN u_char buff[BUFFSIZE+1];
EXTERN u_char line[BUFFSIZE+1];
EXTERN char ptybuff[BUFFSIZE+1];
EXTERN char ipaddr[20];
EXTERN char *log_file;
EXTERN int buffpos;
EXTERN int sock;
EXTERN int term_height;
EXTERN int term_width;
EXTERN int listen_sock;

/* Child */
EXTERN struct passwd *userinfo;
EXTERN struct passwd god_userinfo;
EXTERN sigset_t sigmask;
EXTERN pid_t master_pid;
EXTERN pid_t slave_pid;
EXTERN int state;
EXTERN int ptym;
EXTERN int ptys;
EXTERN int attempts;
EXTERN int line_buffpos;
EXTERN int login_exec_argv_cnt;
EXTERN char prev_c;
EXTERN char *telopt_username;
EXTERN char **shell_exec_argv;
EXTERN char **login_exec_argv;

/* config.c */
void parseConfigFile();

/* master_child.c */
void runMaster();
void setUserNameAndPwdState(char *uname);
int  loginAllowed(char *uname);
void checkLoginAttempts();
void storeWinSize();
void masterExit(int code);

/* slave_child.c */
void runSlave();
void notifyWinSize();

/* pty.c */
int  openPTYMaster();
int  openPTYSlave();
char *getPTYName();

/* io.c */
void readPtyMaster();
void readSock();
void writeSock(char *data, int len);
void writeSockStr(char *data);
void sockprintf(char *fmt, ...);
void logprintf(pid_t pid, char *fmt, ...);

/* telopt.c */
void sendInitialTelopt();
u_char *parseTelopt(u_char *p, u_char *end);

/* split.c */
char *splitString(char *str, char *end, char ***words, int *word_cnt);
void  addWordToArray(char ***words, char *word, char *end, int *word_cnt);
void  freeWords(char **words, int word_cnt);

/* misc.c */
void setState(int st);

