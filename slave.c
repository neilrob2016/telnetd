/*****************************************************************************
 This is the slave side of the PTY which is dup'ed onto stdin/out/err so that 
 the shell process reads/writes direct to the PTY which is picked up by the
 master child. 
 *****************************************************************************/
 
#include "globals.h"

extern char **environ;

static void addUtmpEntry(void);


/*** Fork off slave child process that will run bash/login ***/
void runSlave(void)
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
		/* In slave child process here */
		slave_pid = getpid();
		logprintf(slave_pid,"STARTED: Slave process, ppid = %d.\n",master_pid);

		/* Use setsid() so that when we open the pty slave it
		   becomes the controlling tty */
		if (setsid() == -1)
			logprintf(slave_pid,"ERROR: setsid(): %s\n",strerror(errno));

		if (!openPTYSlave()) exit(1);
		notifyWinSize();

		/* Tell parent we're running */
		kill(getppid(),SIGUSR1);

		/* Reset signals back to their default except for handled ones
		   which gets doe automatically by exec() */
		signal(SIGCHLD,SIG_DFL);
		signal(SIGHUP,SIG_DFL);
		sigprocmask(SIG_UNBLOCK,&sigmask,NULL);

		if (shell_exec_argv)
		{
			logprintf(slave_pid,"Setting up enviroment for user \"%s\", uid %d...\n",
				username,userinfo->pw_uid);

			/* Add manually if exec'ing shell. /bin/login does it
			   itself. Do it before we setuid as must be root. */
			addUtmpEntry();

			/* Do this before we switch user */
			if (setgid(userinfo->pw_gid) == -1)
			{
				logprintf(slave_pid,"ERROR: setgid(%d): %s\n",
					userinfo->pw_gid,strerror(errno));
			}

			/* Switch to login user id */
			if (setuid(userinfo->pw_uid) == -1)
			{
				logprintf(slave_pid,"ERROR: setuid(%d): %s\n",
					userinfo->pw_uid,strerror(errno));
			}
			if (chdir(userinfo->pw_dir) == -1)
			{
				logprintf(slave_pid,"ERROR: chdir(\"%s\"): %s\n",
					userinfo->pw_dir,strerror(errno));
			}
			setenv("HOME",userinfo->pw_dir,1);

			prog = shell_exec_argv[0];
			exec_argv = shell_exec_argv;

			logprintf(slave_pid,"Executing shell program \"%s\"...\n",prog);
		}
		else
		{
			if (!flags.append_user) telopt_username = NULL;

			/* Login program and args given in .cfg */
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
				/* No login or shell program given in config 
				   so use default system one. */
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

			logprintf(slave_pid,"Executing login program \"%s\"...\n",prog);
		}

		/* Redirect I/O to pty slave */
		dup2(ptys,STDIN);
		dup2(ptys,STDOUT);
		dup2(ptys,STDERR);

		/* Exec logon/shell */
		execve(prog,exec_argv,environ);

		/* Don't write if the log goes to stdout as I/O has been
		   redirected to the shell/login process and will be seen by
		   the user so they'll get 2 error messages */
		if (log_file)
		{
			logprintf(slave_pid,"ERROR: Exec failed: %s\n",
				strerror(errno));
		}
		sockprintf("ERROR: Exec of \"%s\" failed: %s\n",
			exec_argv[0],strerror(errno));
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
void notifyWinSize(void)
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
     command etc. The entry is removed automatically by the OS when the process
     exits. ***/
void addUtmpEntry(void)
{
	struct utmpx entry;

	bzero(&entry,sizeof(entry));
	entry.ut_type = USER_PROCESS;
	entry.ut_pid = getpid();

	/* Using the min lengths I found for these fields */
	snprintf(entry.ut_user,32,"%s",userinfo->pw_name);
	snprintf(entry.ut_line,32,"%s",getPTYName());
	if (flags.store_host_in_utmp)
	{
		if (dnsaddr)
			snprintf(entry.ut_host,256,"%s - %s",ipaddrstr,dnsaddr);
		else
			snprintf(entry.ut_host,256,"%s",ipaddrstr);
	}

	time((time_t *)&entry.ut_tv.tv_sec);

	/* Move to start of utmp file */
	setutxent();
	if (!pututxline(&entry))
		logprintf(slave_pid,"ERROR: addUtmpEntry(): pututxline(): %s\n",strerror(errno));
}
