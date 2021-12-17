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
}




void logprintf(pid_t pid, char *fmt, ...)
{
	struct tm *tms;
	va_list args;
	FILE *fp;
	time_t now;
	char tstr[30];
	char pre[40];
	char *fstr;
	int fd;
	int i;

	/* Don't print to stdout if we're a daemon */
	if (!log_file && flags.daemon) return;

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
			/* Try and get a lock. If we can't after a short time
			   just give up */
			fd = fileno(fp);
			for(i=0;
			    i < 5 && flock(fd,LOCK_EX | LOCK_NB) == EWOULDBLOCK;
			    ++i) 
			{
				/* Tiny delay so user doesn't notice */
				usleep(1000);
			}
			if (i < 5)
				fprintf(fp,"%s%s",pre,fstr);
			else
				fprintf(stderr,"ERROR: logprintf(): Failed to get file lock.\n");
			fclose(fp);
		}
		else fprintf(stderr,"ERROR: logprintf(): fopen(): %s\n",strerror(errno));
	}
	else 
	{
		printf("%s%s",pre,fstr);
		fflush(stdout);
	}
	free(fstr);
}
