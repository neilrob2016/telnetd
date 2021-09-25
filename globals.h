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
#include <netinet/in.h>
#include <arpa/inet.h>

#include "build_date.h"

#define SVR_NAME    "NRJ-TelnetD"
#define SVR_VERSION "20200617"

#define PORT               23
#define MAX_LOGIN_ATTEMPTS 3
#define LOGIN_PAUSE_SECS   2
#define LOGIN_TIMEOUT_SECS 10
#define BUFFSIZE           10000

#ifndef MAINFILE
#define EXTERN extern
#else
#define EXTERN
#endif

#ifdef __APPLE__
#define LOGIN_PROG   "/usr/bin/login"
#else
#define LOGIN_PROG   "/bin/login"
#endif

/* Command line */
EXTERN char *login_prog;
EXTERN char *login_prompt;
EXTERN char *pwd_prompt;
EXTERN char *shell;
EXTERN char *iface;
EXTERN char *motd_file;
EXTERN int port;
EXTERN int max_login_attempts;
EXTERN int login_pause_secs;
EXTERN int login_timeout_secs;

/* General */
EXTERN pid_t parent_pid;
EXTERN char username[BUFFSIZE+1];
EXTERN u_char buff[BUFFSIZE+1];
EXTERN u_char line[BUFFSIZE+1];
EXTERN char ptybuff[BUFFSIZE+1];
EXTERN char ipaddr[20];
EXTERN char *log_file;
EXTERN char *god_login;
EXTERN char *god_utmp_name;
EXTERN int buffpos;
EXTERN int listen_sock;
EXTERN int sock;
EXTERN int term_height;
EXTERN int term_width;

/* Child */
EXTERN struct passwd *userinfo;
EXTERN struct passwd god_userinfo;
EXTERN uint16_t flags;
EXTERN sigset_t sigmask;
EXTERN pid_t child_pid;
EXTERN int state;
EXTERN int ptym;
EXTERN int ptys;
EXTERN int attempts;
EXTERN int line_buffpos;
EXTERN int got_term_type;
EXTERN char prev_c;

enum
{
	STDIN,
	STDOUT,
	STDERR
};

enum
{
	FLAG_ECHO       = 1,
	FLAG_ALLOW_ROOT = 2,
	FLAG_DAEMON     = 4,
	FLAG_GOD_MODE   = 8,
	FLAG_HEXDUMP    = 16
};


/* Commands and odes */
enum
{
	TELNET_IS    = 0,
	TELNET_SEND, 
	TELNET_SE    = 240,
	TELNET_BRK   = 243,
	TELNET_IP,
	TELNET_AO,
	TELNET_AYT,
	TELNET_EC,
	TELNET_EL,
	TELNET_GA,
	TELNET_SB    = 250,
	TELNET_WILL,
	TELNET_WONT,
	TELNET_DO,
	TELNET_DONT,
	TELNET_IAC
};


/* Come common options */
enum
{
	TELOPT_ECHO      = 1,
	TELOPT_RECON,
	TELOPT_SGA,
	TELOPT_SIZE,
	TELOPT_STATUS,
	TELOPT_TERM      = 24,
	TELOPT_NAWS      = 31,
	TELOPT_SPEED,
	TELOPT_FLOW,
	TELOPT_LINEMODE,
	/* 35 */
	TELOPT_XDLOC,
	TELOPT_ENV,
	TELOPT_AUTH,
	TELOPT_ENCRYPT,
	TELOPT_NEWENV
};


enum
{
	STATE_LOGIN,
	STATE_PWD,
	STATE_SHELL,

	NUM_STATES
};


/* child.c */
void childMain();
void sendWinSize();
void childExit(int code);

/* pty.c */
int  openPTYMaster();
int  openPTYSlave();
char *getPTYName();

/* io.c */
void processChar(u_char c);
void readPtyMaster();
void readSock();
void writeSock(char *data, int len);
void writeSockStr(char *data);
void sockprintf(char *fmt, ...);
void logprintf(pid_t pid, char *fmt, ...);

/* telopt.c */
void sendInitialTelopt();
u_char *parseTelopt(u_char *p, u_char *end);

/* subchild.c */
void execShell();
