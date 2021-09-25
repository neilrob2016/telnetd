#include "globals.h"


/*** Open and set up the pty master. This is the network side of the PTY so
     data read from the socket get written to this and data from this gets
     sent down the socket. ***/
int openPTYMaster()
{
	if ((ptym = posix_openpt(O_RDWR | O_NOCTTY)) == -1)
	{
		sockprintf("ERROR: posix_openpt(): %s\n",strerror(errno));
		return 0;
	}

	if (grantpt(ptym) == -1)
	{
		sockprintf("ERROR: grantpt(): %s\n",strerror(errno));
		close(ptym);
		return 0;
	}

	if (unlockpt(ptym) == -1)
	{
		sockprintf("ERROR: unlockpt(): %s\n",strerror(errno));
		close(ptym);
		return 0;
	}
	return 1;
}




/*** Open the PTY slave which is the other end of the PTY pipe and is the
     controlling terminal of login/shell which read and write to this. ***/
int openPTYSlave()
{
	if ((ptys = open((char *)ptsname(ptym),O_RDWR)) == -1)
	{
		sockprintf("ERROR: open(): %s\n",strerror(errno));
		return 0;
	}
	return 1;
}




char *getPTYName()
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
