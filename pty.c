#include "globals.h"


/*** Open and set up the pty master. This is the network side of the PTY so
     data read from the socket get written to this and data from this gets
     sent down the socket. ***/
int openPTYMaster(void)
{
	if ((ptym = posix_openpt(O_RDWR | O_NOCTTY)) == -1)
	{
		logprintf(master_pid,"ERROR: openPTYMaster(): posix_openpt(): %s\n",
			strerror(errno));
		goto ERROR;
	}

	if (grantpt(ptym) == -1)
	{
		logprintf(master_pid,"ERROR: openPTYMaster(): grantpt(): %s\n",
			strerror(errno));
		close(ptym);
		goto ERROR;
	}

	if (unlockpt(ptym) == -1)
	{
		logprintf(master_pid,"ERROR: openPTYMaster(): unlockpt(): %s\n",
			strerror(errno));
		close(ptym);
	}
	else return 1;

	ERROR:
	sockprintf("ERROR: Open PTY master failed, can't continue.\n");
	return 0;
}




/*** Open the PTY slave which is the other end of the PTY pipe and is the
     controlling terminal of login/shell which read and write to this. ***/
int openPTYSlave(void)
{
	if ((ptys = open((char *)ptsname(ptym),O_RDWR)) == -1)
	{
		sockprintf("ERROR: Open PTY slave failed, can't continue.\n");
		logprintf(slave_pid,"ERROR: openPTYSlave(): open(): %s\n",
			strerror(errno));
		return 0;
	}
	return 1;
}




char *getPTYName(void)
{
	char *ptr;

	/* Skip /dev/ part of the path at the start */
	if ((ptr = ptsname(ptym)))
	{
		if (!strncmp(ptr,"/dev/",5)) return ptr+5;
		return ptr;	
	}
	return "??";
}
