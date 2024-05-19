#include "globals.h"

st_ip parseIP(char *addrstr)
{
	st_ip ip;
	int32_t octet;
	int addrstrlen;
	int len;
	int cnt;
	int shift;
	char *ptr;
	char *ptr2;
	char *end;
	char c;

	bzero(&ip,sizeof(ip));

	/* Must be a min of N.N.N.N */
	if ((addrstrlen = strlen(addrstr)) < 7) goto INVALID;
	end = addrstr + addrstrlen;

	for(ptr=addrstr,cnt=shift=0;ptr < end;ptr=ptr2+1,++cnt,shift+=8)
	{
		/* Get octet */
		if (!(ptr2 = strchr(ptr,'.'))) ptr2 = addrstr + addrstrlen;
		len = (int)(ptr2 - ptr);
		switch(len)
		{
		case 1:
			if (*ptr == '*') ip.mask |= (0xFF << shift);
			else if (!isdigit(*ptr)) goto INVALID;
			break;
		case 2:
			if (!isdigit(*ptr) || !isdigit(*(ptr+1))) goto INVALID;
			break;
		case 3:
			if (!isdigit(*ptr) || 
			    !isdigit(*(ptr+1)) ||
			    !isdigit(*(ptr+2))) goto INVALID;
			break;
		default:
			goto INVALID;
		}
		c = *ptr2;
		*ptr2 = 0;
		octet = (uint32_t)atoi(ptr);
		*ptr2 = c;
		if (octet > 255) goto INVALID;
		ip.addr |= octet << shift;
		if (!*ptr) break;
	}
	if (cnt == 4) 
	{
		/* Flip all the bits in the mask. eg if we have 127.*.0.* we 
		   want a mask of 0xFF00FF00 */
		ip.mask = htonl(ip.mask ^ 0xFFFFFFFF);
		ip.addr = htonl(ip.addr);
		ip.maskaddr = (ip.addr & ip.mask);
		ip.str = strdup(addrstr);
		return ip;
	}

	INVALID:
	logprintf(0,"ERROR: Invalid ip address \"%s\".\n",addrstr);
	parentExit(-1);
	return ip;
}




void addToIPList(st_ip ip)
{
	/* There won't be many so don't need to preallocate for efficiency */
	iplist = (st_ip *)realloc(iplist,sizeof(st_ip) * ++iplist_cnt);
	assert(iplist);
	iplist[iplist_cnt-1] = ip;
}




int authorisedIP(struct sockaddr_in *ip_addr)
{
	uint32_t addr = ntohl(ip_addr->sin_addr.s_addr);
	int i;

	if (!iplist_cnt) return 1;

	for(i=0;i < iplist_cnt;++i)
	{
		/* The mask makes sure we only compare the octets we care 
		   about. Eg for 127.*.0.* and an address of 127.0.0.1 we'll
		   only compare 127.-.0.- */
		if (iplist[i].addr == addr ||
		    iplist[i].maskaddr == (addr & iplist[i].mask))
		{
			return iplist_type == IP_WHITELIST ? 1 : 0;
		}
	}
	return 0;
}
