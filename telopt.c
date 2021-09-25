/*****************************************************************************
 Processes telnet control options.

 https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
 *****************************************************************************/

#include "globals.h"


void sendResponse(u_char com, u_char opt);
void requestSubOption(u_char sb);
u_char *getTermSize(u_char *p, u_char *end);
u_char *getTermType(u_char *p, u_char *end);
u_char *findSubOptEnd(u_char *p, u_char *end);


/*** Send request for client to enter char mode, not to echo , to send
     terminal type, terminal/window size and X display string ***/
void sendInitialTelopt()
{
	char mesg[13];
	sprintf(mesg,"%c%c%c%c%c%c%c%c%c%c%c%c",
		TELNET_IAC,TELNET_WILL,TELOPT_SGA,
		TELNET_IAC,TELNET_WILL,TELOPT_ECHO,
		TELNET_IAC,TELNET_DO,TELOPT_TERM,
		TELNET_IAC,TELNET_DO,TELOPT_NAWS);
	writeSock(mesg,12);
}




/*** We have a telopt code starting at address p. If the telopt is incomplete
     this returns null else it returns a pointer to last character in the 
     sequence ***/
u_char *parseTelopt(u_char *p, u_char *end)
{
	u_char com;
	u_char opt;
	int len;

	len = (int)(end - p);

	if (len < 2) return NULL;
	com = *(p + 1);
	if (len > 2) opt = *(p + 2);	

	/* IAC BRK/IP/AO/AYT/EC/EL
	   IAC WILL/WONT/DO/DONT <option>          or
	   IAC SB NAWS x x x x IAC SE              or
	   IAC SB TERM IS <terminal type> IAC SE  */
	switch(com)
	{
	case TELNET_BRK:
		return p+1;

	case TELNET_IP:
		return p+1;

	case TELNET_AO:
		return p+1;

	case TELNET_AYT:
		return p+1;

	case TELNET_EC:
		return p+1;

	case TELNET_EL:
		return p+1;

	case TELNET_GA:
		return p+1;
		
	case TELNET_SB:
		if (len < 3) return NULL;

		switch(opt)
		{
		case TELOPT_NAWS:
			return getTermSize(p+3,end);
			break;

		case TELOPT_TERM:
			return getTermType(p+3,end);
		}
		logprintf(child_pid,"TELNET: Unexpected SB option %u\n",(u_char)opt);
		return findSubOptEnd(p+3,end);

	case TELNET_WILL:
		if (len < 3) return NULL;

		switch(opt)
		{
		case TELOPT_NAWS:
			/* No response since we sent initial DO */
			break;

		case TELOPT_TERM:
			requestSubOption(TELOPT_TERM);
			break;

		case TELOPT_SPEED:
		case TELOPT_FLOW:
		case TELOPT_LINEMODE:
		case TELOPT_XDLOC:
		case TELOPT_AUTH:
		case TELOPT_NEWENV:
			/* Seem to be sent by telnet client when on port 23, 
			   but we don't want it to do any of these */
			sendResponse(TELNET_DONT,opt);
			break;
		
		default:
			logprintf(child_pid,"TELNET: Unexpected WILL option %u\n",
				(u_char)opt);
			sendResponse(TELNET_DONT,opt);
			break;
		}

		return p+2;

	case TELNET_WONT:
		if (len < 3) return NULL;

		switch(opt)
		{
		case TELOPT_NAWS:
			sockprintf("TELNET: WARNING: Can't get terminal size.\n");
			sendWinSize();
			break;

		case TELOPT_TERM:
			sockprintf("TELNET: WARNING: Can't get terminal type.\n");
			break;

		default:
			logprintf(child_pid,"TELNET: Unexpected WONT option %u\n",
				(u_char)opt);
			break;
		}

		return p+2;

	case TELNET_DO:
		switch(opt)
		{
		case TELOPT_SGA:
			/* No response since we sent the initial WILL */
			break;

		case TELOPT_ECHO:
			/* Ditto above */
			flags |= FLAG_ECHO;
			break;

		case TELOPT_STATUS:
			sendResponse(TELNET_WONT,opt);
			break;

		default:
			logprintf(child_pid,"TELNET: Unexpected DO option %u\n",
				(u_char)opt);
			sendResponse(TELNET_WONT,opt);
			break;
		}
		return p+2;

	case TELNET_DONT:
		if (len < 3) return NULL;

		switch(opt)
		{
		case TELOPT_SGA:
			sockprintf("TELNET: ERROR: Client does not support character mode.\n");
			childExit(1);
		case TELOPT_ECHO:
			break;

		default:
			logprintf(child_pid,"TELNET: Unexpected DONT option %u\n",
				(u_char)opt);
			break;
		}
		return p+2;
	}

	return p+1;
}




void sendResponse(u_char com, u_char opt)
{
	u_char mesg[3];
	mesg[0] = TELNET_IAC;
	mesg[1] = com;
	mesg[2] = opt;
	writeSock((char *)mesg,3);
}




/*** Send a request for a sub comoption ***/
void requestSubOption(u_char sb)
{
	char mesg[7];
	sprintf(mesg,"%c%c%c%c%c%c",
		TELNET_IAC,TELNET_SB,sb,TELNET_SEND,TELNET_IAC,TELNET_SE);
	writeSock(mesg,6);
}




/*** Get the terminal size: IAC SB NAWS x x x x IAC SE ***/
u_char *getTermSize(u_char *p, u_char *end)
{
	uint16_t w1,w2;
	uint16_t h1,h2;
	u_char *e;

	/* p should start at WIDTH1 WIDTH2 HEIGHT1 HEIGHT2 IAC SE */
	if (end - p < 6) return NULL;

	/* 255 could be duplicated so make sure we have the SE */
	if (!(e = findSubOptEnd(p,end))) return NULL;

	if (*p == 255) ++p;
	if (p == e) return e; /* In case of buffer overrun attempt */
	w1 = *p++;

	if (*p == 255) ++p;
	if (p == e) return e;
	w2 = *p++;

	if (*p == 255) ++p;
	if (p == e) return e;
	h1 = *p++;

	if (*p == 255) ++p;
	if (p == e) return e;
	h2 = *p++;
	
	/* 16 bit data fields are sent big endian */
	term_width = (w1 << 8) + w2;
	term_height = (h1 << 8) + h2;

	logprintf(child_pid,"Terminal size: %d,%d\n",term_width,term_height);
	sendWinSize();
	return e;
}




/*** Get the terminal type: IAC SB TERM IS <terminal type> IAC SE ***/
u_char *getTermType(u_char *p, u_char *end)
{
	u_char *e;
	u_char *p2;

	/* p should start at IS <terminal type> IAC SE though it could be
	   an empty string hence < 3 not < 4 */
	if (end - p < 3 || *p != TELNET_IS) return NULL;

	/* Find the SE */
	if (!(e = findSubOptEnd(p,end))) return NULL;

	/* Client seems to send in uppercase, convert to lower as some
	   programs care */
	for(p2=++p;*p2;++p2) *p2 = tolower(*p2);

	logprintf(child_pid,"Terminal type: '%s'\n",p);

	/* Want it passed down to slave child processes. If there's a way to
	   do it using ioctl() as per terminal size I can't find it. */
	setenv("TERM",(char *)p,1);
	got_term_type = 1;

	return e;
}




/*** Find the end of the sub option which should be IAC SE ***/
u_char *findSubOptEnd(u_char *p, u_char *end)
{
	int cnt;
	u_char *e;

	for(e=p+1,cnt=0;e < end;++e)
	{
		if (cnt && *e == TELNET_SE) break;
		if (*e == TELNET_IAC) cnt = 1; else cnt = 0;
	}
	if (e == end) return NULL;
	*(e - 1) = 0; /* For string printing */
	return e;
}
