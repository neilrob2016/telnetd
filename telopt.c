/*****************************************************************************
 Processes telnet control options.

 https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
 *****************************************************************************/

#include "globals.h"

#define IS_VAR_START(C) (C == NEW_ENV_VAR || C == ENV_USERVAR)

void sendResponse(u_char com, u_char opt);
void requestSubOption(u_char sb);
u_char *getTermSize(u_char *p, u_char *end);
u_char *getTermType(u_char *p, u_char *end);
u_char *getEnviroment(u_char *p, u_char *end);
u_char *findSubOptEnd(u_char *p, u_char *end);


/*** Send request for client to enter char mode, not to echo , to send
     terminal type, terminal/window size and X display string ***/
void sendInitialTelopt(void)
{
	static u_char mesg[15] = 
	{
		TELNET_IAC,TELNET_WILL,TELOPT_SGA,
		TELNET_IAC,TELNET_WILL,TELOPT_ECHO,
		TELNET_IAC,TELNET_DO,TELOPT_TTYPE,
		TELNET_IAC,TELNET_DO,TELOPT_NAWS,
		TELNET_IAC,TELNET_DO,TELOPT_NEW_ENVIRON
	};
	writeSock(mesg,15);
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
	   IAC SB TERM IS <terminal type> IAC SE  
	   IAC SB NEW_ENVIRON IS/INFO <enviroment vars> IAC SE */
	switch(com)
	{
	case TELNET_BRK:
	case TELNET_IP:
	case TELNET_AO:
	case TELNET_AYT:
	case TELNET_EC:
	case TELNET_EL:
	case TELNET_GA:
		break;

	case TELNET_SB:
		if (len < 3) return NULL;
		if (state != STATE_TELOPT && opt != TELOPT_NAWS)
		{
			logprintf(master_pid,"TELOPT: Ignoring SB option %d, wrong state.\n",opt);
			return findSubOptEnd(p+3,end);
		}
		switch(opt)
		{
		case TELOPT_NAWS:
			return getTermSize(p+3,end);
			break;

		case TELOPT_TTYPE:
			return getTermType(p+3,end);

		case TELOPT_NEW_ENVIRON:
			return getEnviroment(p+3,end);
		}
		logprintf(master_pid,"TELOPT: Unexpected SB option %u\n",(u_char)opt);
		return findSubOptEnd(p+3,end);

	case TELNET_WILL:
		if (len < 3) return NULL;
		if (state != STATE_TELOPT)
		{
			logprintf(master_pid,"TELOPT: Ignoring WILL option %d, wrong state.\n",opt);
			return findSubOptEnd(p+3,end);
		}
		switch(opt)
		{
		case TELOPT_NAWS:
			/* No response since we sent initial DO */
			break;

		case TELOPT_TTYPE:
			requestSubOption(TELOPT_TTYPE);
			break;

		case TELOPT_NEW_ENVIRON:
			requestSubOption(TELOPT_NEW_ENVIRON);
			break;
		
		default:
			logprintf(master_pid,"TELOPT: Refusing WILL option %u\n",
				(u_char)opt);
			sendResponse(TELNET_DONT,opt);
			break;
		}
		return p+2;

	case TELNET_WONT:
		if (len < 3) return NULL;
		if (state != STATE_TELOPT)
		{
			logprintf(master_pid,"TELOPT: Ignoring WONT option %d, wrong state.\n",opt);
			return findSubOptEnd(p+3,end);
		}
		switch(opt)
		{
		case TELOPT_NAWS:
			logprintf(master_pid,"TELOPT: Client WONT terminal size.\n");
			sockprintf("Your client refused to send terminal size.\n");
			break;

		case TELOPT_TTYPE:
			logprintf(master_pid,"TELOPT: Client WONT terminal type.\n");
			sockprintf("Your client refused to send terminal type.\n");
			/* So we don't keep waiting for it */
			flags.rx_ttype = 1;
			break;

		case TELOPT_NEW_ENVIRON:
			logprintf(master_pid,"TELOPT: Client WONT enviroment vars.\n");
			sockprintf("Your client refused to send enviroment variables.\n");
			flags.rx_env = 1;
			break;

		default:
			logprintf(master_pid,"TELOPT: Unexpected WONT option %u\n",
				(u_char)opt);
			break;
		}
		return p+2;

	case TELNET_DO:
		if (state != STATE_TELOPT)
		{
			logprintf(master_pid,"TELOPT: Ignoring DO option %d, wrong state.\n",opt);
			return findSubOptEnd(p+3,end);
		}
		switch(opt)
		{
		case TELOPT_SGA:
			/* No response since we sent the initial WILL */
			break;

		case TELOPT_ECHO:
			/* Ditto above */
			flags.echo = 1; 
			break;

		default:
			logprintf(master_pid,"TELOPT: Refusing DO option %u\n",
				(u_char)opt);
			sendResponse(TELNET_WONT,opt);
			break;
		}
		return p+2;

	case TELNET_DONT:
		if (len < 3) return NULL;
		if (state != STATE_TELOPT)
		{
			logprintf(master_pid,"TELOPT: Ignoring DONT option %d, wrong state.\n",opt);
			return findSubOptEnd(p+3,end);
		}

		switch(opt)
		{
		case TELOPT_SGA:
			logprintf(master_pid,"TELOPT: Client does not support character mode, exiting.\n");
			sockprintf("ERROR: Your client does not support character mode, cannot continue.\n");
			masterExit(1);
		case TELOPT_ECHO:
			break;

		default:
			logprintf(master_pid,"TELOPT: Unexpected DONT option %u\n",
				(u_char)opt);
			break;
		}
		return p+2;

	default:
		logprintf(master_pid,"TELOPT: Unexpected command/option %d\n",com);
		break;
	}

	return p+1;
}




void sendResponse(u_char com, u_char opt)
{
	u_char mesg[3] = { TELNET_IAC, com, opt };
	writeSock(mesg,3);
}




/*** Send a request for a sub comoption ***/
void requestSubOption(u_char sb)
{
	u_char mesg[6] =
	{
		TELNET_IAC,TELNET_SB,sb,
		TELQUAL_SEND,TELNET_IAC,TELNET_SE
	};
	writeSock(mesg,6);
}




/*** Get the terminal size: IAC SB NAWS x x x x IAC SE ***/
u_char *getTermSize(u_char *p, u_char *end)
{
	uint16_t w1,w2;
	uint16_t h1,h2;

	/* p should start at WIDTH1 WIDTH2 HEIGHT1 HEIGHT2 IAC SE */
	if (end - p < 6) return NULL;

	/* 255 could be duplicated so make sure we have the SE */
	if (!(end = findSubOptEnd(p,end))) return NULL;

	if (*p == 255) ++p;
	if (p == end) return end; /* In case of buffer overrun attempt */
	w1 = *p++;

	if (*p == 255) ++p;
	if (p == end) return end;
	w2 = *p++;

	if (*p == 255) ++p;
	if (p == end) return end;
	h1 = *p++;

	if (*p == 255) ++p;
	if (p == end) return end;
	h2 = *p++;
	
	/* 16 bit data fields are sent big endian */
	term_width = (w1 << 8) + w2;
	term_height = (h1 << 8) + h2;

	/* Could be a ton of these which could create a huge amount of log 
	   so there's an enabling flag */
	if (flags.show_term_resize)
	{
		logprintf(master_pid,"TELOPT: Terminal size = %d,%d\n",
			term_width,term_height);
	}

	/* Have to do this to keep shell updated as client will send NAWS
	   when the xterm is resized */
	notifyWinSize();
	return end;
}




/*** Get the terminal type: IAC SB TERM IS <terminal type> IAC SE ***/
u_char *getTermType(u_char *p, u_char *end)
{
	u_char *p2;

	/* p should start at IS <terminal type> IAC SE though it could be
	   an empty string hence < 3 not < 4 */
	if (end - p < 3 || *p != TELQUAL_IS) return NULL;

	/* Find the SE */
	if (!(end = findSubOptEnd(p,end))) return NULL;

	/* Client seems to send in uppercase, convert to lower as some
	   programs care and remove non printing chars that have snuck in */
	for(p2=++p;*p2 && p2 < end;++p2)
	{
		if (*p2 < 32) *p2 = ' ';
		*p2 = tolower(*p2);
	}
	logprintf(master_pid,"TELOPT: Terminal type = \"%s\"\n",p);

	/* Want it passed down to slave child processes. If there's a way to
	   do it using ioctl() as per terminal size I can't find it. */
	setenv("TERM",(char *)p,1);
	flags.rx_ttype = 1;

	return end;
}




/*** Get the enviroment:
     IAC SB NEW_ENVIRON IS/INFO \
     [NEW_ENV_VAR/ENV_USERVAR <var name> NEW_ENV_VALUE <value>] * N
     IAC SE ***/
u_char *getEnviroment(u_char *p, u_char *end)
{
	u_char *e;
	char *varname;
	int get_var_name;
	int len;
	
	if (*p != TELQUAL_IS && *p != TELQUAL_INFO) return NULL;

	/* Find the SE */
	if (!(end = findSubOptEnd(p,end))) return NULL;

	flags.rx_env = 1;

	/* Can get an empty list so just return if this is the case */
	++p;
	if (!IS_VAR_START(*p)) return end;
	get_var_name = 1;

	for(e=++p;e < end;++e)
	{
		if (get_var_name)
		{
			if (*e == NEW_ENV_VALUE)
			{
				len = (int)(e-p);
				if (!len)
				{
					/* Bail out if there's corruption */
					logprintf(master_pid,"TELOPT: WARNING: Zero length env var name.\n");
					return end;
				}
				*e = 0;
				varname = (char *)p;
				get_var_name = 0;
				p = e+1;
			}
		}
		else if (IS_VAR_START(*e))
		{
			len = (int)(e-p);
			if (len)
			{
				*e = 0;
				setenv(varname,(char *)p,1);
				logprintf(master_pid,
					"TELOPT: Env var = \"%s\", value = \"%s\"\n",
					varname,p);

				/* Store username for login program */
				if (!telopt_username &&
				    !strcmp(varname,"USER"))
				{
					telopt_username = strdup((char *)p);
				}
			}
			else setenv(varname,"",1);
			get_var_name = 1;
			p = e+1;
		}
		/* Non printing shouldn't be in the data but just in case */
		else if (*e < 32) *e = ' '; 
	}
	if (!get_var_name)
	{
		/* Expecting matching value for variable */
		logprintf(master_pid,"TELOPT: WARNING: Unexpected end of enviroment variable list.");
	}
	return end;
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
