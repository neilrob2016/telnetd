#include "globals.h"


/*** Do a printf down the socket ***/
void sockprintf(char *fmt, ...)
{
	va_list args;
	u_char out1[BUFFSIZE];
	u_char out2[BUFFSIZE*2];
	u_char *s1;
	u_char *s2;

	va_start(args,fmt);
	vsnprintf((char *)out1,BUFFSIZE,fmt,args);
	va_end(args);

	/* Convert \n to \r\n */
	for(s1=out1,s2=out2;*s1;++s1,++s2)
	{
		if (*s1 == '\n') *s2++ = '\r';
		*s2 = *s1;
	}
	*s2 = 0;

 	writeSockStr((char *)out2);

	/* Only print if child process, not sub child */
	if (getpid() == child_pid) logprintf(child_pid,(char *)out2);
}




void logprintf(pid_t pid, char *fmt, ...)
{
	va_list args;
	FILE *fp;
	struct tm *tms;
	time_t now;
	char tstr[30];
	char pre[40];
	char *fstr;

	/* Don't print to stdout if we're a daemon */
	if (!log_file && (flags & FLAG_DAEMON)) return;

	time(&now);
	tms = localtime(&now);
	strftime(tstr,sizeof(tstr),"%F %T",tms);
	sprintf(pre,"%s: %d: ",tstr,pid);

	va_start(args,fmt);
	if (vasprintf(&fstr,fmt,args) == -1)
	{
		va_end(args);
		return;
	}
	va_end(args);

	if (log_file)
	{
		if ((fp = fopen(log_file,"a")))
		{
			fprintf(fp,"%s%s",pre,fstr);
			fclose(fp);
		}
	}
	else 
	{
		printf("%s%s",pre,fstr);
		fflush(stdout);
	}
	free(fstr);
}
