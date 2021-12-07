/*****************************************************************************
 This is the slave side of the PTY which is dup'ed onto stdin/out/err so that 
 the shell process reads/writes direct to the PTY which is picked up by the
 master child. 
 *****************************************************************************/
 
#include "globals.h"

extern char **environ;

void addUtmpEntry();


/*** Fork off slave child process that will run bash/login ***/
void runSlave()
{
	char **exec_argv;
	char *def_exec_argv[3];
	char *prog;
	int sig;

	state = STATE_SHELL;
	notifyWinSize();

	/* Execute sub child to run the shell process */
	switch((slave_pid = fork()))
	{
	case -1:
		sockprintf("ERROR: Can't fork.\n");
		logprintf(master_pid,"ERROR: execSlave(): fork(): %s\n",strerror(errno));
		return;

	case 0:
		slave_pid = getpid();

		/* In slave child process here */
		logprintf(slave_pid,"Slave process STARTED.\n");

		/* Use setsid() so that when we open the pty slave it
		   becomes the controlling tty */
		setsid();

		if (!openPTYSlave())
		{
			sockprintf("ERROR: Open PTY slave failed.\n");
			exit(1);
		}

		/* Tell parent we're running */
		kill(getppid(),SIGUSR1);

		/* Reset signals back to their default except for handled ones
		   which gets done automatically by exec() */
		signal(SIGCHLD,SIG_DFL);
		signal(SIGHUP,SIG_DFL);
		sigprocmask(SIG_UNBLOCK,&sigmask,NULL);

		/* Shell is not an option for MacOS because the password
		   checking code in checkLogin() only works under linux */
		if (shell_exec_argv)
		{
			logprintf(slave_pid,"Executing shell process...\n");

			/* Add manually if exec'ing shell. /bin/login does it
			   itself. Do it before we setuid as must be root. */
			addUtmpEntry();

			/* Switch to login user ids */
			setuid(userinfo->pw_uid);
			setgid(userinfo->pw_gid);
			chdir(userinfo->pw_dir);
			setenv("HOME",userinfo->pw_dir,1);

			prog = shell_exec_argv[0];
			exec_argv = shell_exec_argv;
		}
		else
		{
			logprintf(slave_pid,"Executing login process...\n");
			if (!(flags & FLAG_APPEND_USER)) telopt_username = NULL;

			if (login_exec_argv)
			{
				if (telopt_username) 
				{
					addWordToArray(
						&login_exec_argv,
						telopt_username,
						NULL,&login_exec_argv_cnt);
				}
				prog = login_exec_argv[0];
				exec_argv = login_exec_argv;
			}
			else
			{
				prog = LOGIN_PROG;
				exec_argv = def_exec_argv;
				exec_argv[0] = prog;
				exec_argv[1] = telopt_username;
				exec_argv[2] = NULL;
			}
		}

		/* Redirect I/O to pty slave */
		dup2(ptys,STDIN);
		dup2(ptys,STDOUT);
		dup2(ptys,STDERR);

		/* Exec logon/shell */
		execve(prog,exec_argv,environ);

		sockprintf("ERROR: Exec failed: %s\n",strerror(errno));
		exit(1);

	default:
		/* Wait for child to tell us its ready. Signal sent above. */
		do
		{
			/* If it errors just exit , who cares */
			if (sigwait(&sigmask,&sig) == -1) break;
		} while(sig != SIGUSR1);
	}
}




/*** Send the window size to the pty master and store in enviroment
     variables ***/
void notifyWinSize()
{
	struct winsize ws;
	char str[10];

	if (ptym == -1) return;

	bzero(&ws,sizeof(ws));
	ws.ws_row = term_height;
	ws.ws_col = term_width;

	ioctl(ptym,TIOCSWINSZ,&ws);

	/* Belt and braces */
	snprintf(str,sizeof(str),"%u",term_width);
	setenv("COLUMNS",str,1);
	snprintf(str,sizeof(str),"%u",term_height);
	setenv("LINES",str,1);
}




/*** If we didn't do this then the user login would be invisible to the 'who'
     command etc. The entry is removed automatically by init when the process 
     exits. Linux only. ***/
void addUtmpEntry()
{
#ifndef __APPLE__
	struct utmp entry;
	bzero(&entry,sizeof(entry));

	entry.ut_type = USER_PROCESS;
	entry.ut_pid = getpid();
	strcpy(entry.ut_user,userinfo->pw_name);
	strcpy(entry.ut_line,getPTYName());
	strcpy(entry.ut_host,ipaddr);
	time((time_t *)&entry.ut_tv.tv_sec);

	/* Move to start of utmp file */
	setutent();

	pututline(&entry);
#endif
}
