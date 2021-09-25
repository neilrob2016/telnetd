/*****************************************************************************
 This is the slave side of the PTY which is dup'ed onto stdin/out/err so that 
 the shell process reads/writes direct to the PTY.
 *****************************************************************************/
 
#include "globals.h"

extern char **environ;
void addUtmpEntry();


/*** Fork off the shell that will run the session ***/
void execShell()
{
	char *exec_argv[3];
	char *prog;
	pid_t cpid;
	int err;
	int sig;

	state = STATE_SHELL;

	/* Execute sub child to run the shell process */
	switch((cpid = fork()))
	{
	case -1:
		err = errno;
		sockprintf("ERROR: fork(): %s\n",strerror(err));
		return;

	case 0:
		logprintf(getpid(),"SLAVE CHILD STARTED\n");

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
		if (shell)
		{
			/* Add manually if exec'ing shell. /bin/login does it
			   itself. Do it before we setuid as must be root. */
			addUtmpEntry();

			/* Switch to login user ids */
			setuid(userinfo->pw_uid);
			setgid(userinfo->pw_gid);
			chdir(userinfo->pw_dir);
			setenv("HOME",userinfo->pw_dir,1);

			/* Set up the shell arguments and run */
			exec_argv[0] = shell;
			exec_argv[1] = "-l";

			prog = shell;
		}
		else
		{
			exec_argv[0] = login_prog;
			exec_argv[1] = NULL;
			prog = login_prog;
		}
		logprintf(getpid(),"Executing '%s'...\n",prog);

		/* Redirect I/O to pty slave */
		dup2(ptys,STDIN);
		dup2(ptys,STDOUT);
		dup2(ptys,STDERR);

		/* Exec logon/shell */
		exec_argv[2] = NULL;
		execve(prog,exec_argv,environ);

		err = errno;
		sockprintf("ERROR: execl(): %s\n",strerror(err));
		exit(1);

	default:
		/* Wait for child to tell us its ready. Signal sent above. */
		do
		{
			/* If it errors just exit , who cares */
			if (sigwait(&sigmask,&sig) == -1) break;
		} while(sig != SIGUSR1);

		sendWinSize();
	}
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
