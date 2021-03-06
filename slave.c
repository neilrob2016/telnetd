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
	char *def_exec_argv[4];
	char *prog;
	int sig;

	/* Execute sub child to run the shell process */
	switch((slave_pid = fork()))
	{
	case -1:
		logprintf(master_pid,"ERROR: execSlave(): fork(): %s\n",
			strerror(errno));
		sockprintf("ERROR: Can't fork slave process.\n");
		return;

	case 0:
		slave_pid = getpid();

		/* In slave child process here */
		logprintf(slave_pid,"Slave process STARTED.\n");

		/* Use setsid() so that when we open the pty slave it
		   becomes the controlling tty */
		setsid();

		if (!openPTYSlave()) exit(1);
		notifyWinSize();

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
			if (!flags.append_user) telopt_username = NULL;

			/* Login program and args given in .cfg? */
			if (login_exec_argv)
			{
				if (telopt_username) 
				{
					sockprintf("%s%s\n",
						login_prompt,telopt_username);
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
				if (telopt_username)
				{
					sockprintf("%s%s\n",
						login_prompt,telopt_username);
				}
				prog = LOGIN_PROG;
				exec_argv = def_exec_argv;
				exec_argv[0] = prog;
				if (flags.preserve_env)
				{
					exec_argv[1] = "-p"; 
					exec_argv[2] = telopt_username;
					exec_argv[3] = NULL;
				}
				else
				{
					exec_argv[1] = telopt_username;
					exec_argv[2] = NULL;
				}
			}
		}

		/* Redirect I/O to pty slave */
		dup2(ptys,STDIN);
		dup2(ptys,STDOUT);
		dup2(ptys,STDERR);

		/* Exec logon/shell */
		execve(prog,exec_argv,environ);

		/* Don't write if the log goes to stdout as that will go to
		   the user */
		if (log_file)
		{
			logprintf(slave_pid,"ERROR: Exec failed: %s\n",
				strerror(errno));
		}
		sockprintf("ERROR: Exec failed, can't continue.\n");
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




/*** Send the window size to the pty master and notify the child ***/
void notifyWinSize()
{
	struct winsize ws;

	assert(ptym != -1);

	bzero(&ws,sizeof(ws));
	ws.ws_row = term_height;
	ws.ws_col = term_width;
	ioctl(ptym,TIOCSWINSZ,&ws);

	/* Slave won't have been created when first telopt NAWS received */
	if (slave_pid != -1) kill(slave_pid,SIGWINCH);
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
