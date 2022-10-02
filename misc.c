#include "globals.h"

void setState(int st)
{
	char *name[NUM_STATES] =
	{
		"NOT SET","TELOPT","LOGIN","PWD","SHELL"
	};
	if (st == state) assert(0);
	logprintf(getpid(),"Setting state to %s (%d)\n",name[st],st);
	if (state == STATE_TELOPT)
		logprintf(getpid(),"Further telopt codes will be ignored.\n");
	state = st;
}




void parentExit(int code)
{
	if (code > 0)
		logprintf(parent_pid,"Parent process EXIT on signal %d.\n",code);
	else
	{
		code = -code;
		logprintf(parent_pid,"Parent process EXIT with code %d.\n",code);
	}
	exit(code);
}
