/*
 * decode.h
 *
 * Protocol decoding routines.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode.h,v 1.5 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef DECODE_H
#define DECODE_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

typedef int (*decode_func)(u_char *, int, u_char *, int);

struct decode {
	char	       *dc_name;
	decode_func	dc_func;
};

// Meta data for decoded items
struct _dc_meta {
	u_char *rbuf;  // reverse connection
	int rlen;
	uint32_t crc;
	int is_hot;  // found a password or vulnerability
};
// ANSI color codes.
#define CDR        "\033[0;31m"
#define CDG        "\033[0;32m"
#define CDY        "\033[0;33m"
#define CDB        "\033[0;34m"
#define CDM        "\033[0;35m"
#define CDC        "\033[0;36m"
#define CDW        "\033[0;37m"
#define CR         "\033[1;31m"
#define CG         "\033[1;32m"
#define CY         "\033[1;33m"
#define CN         "\033[0m"
#define CB         "\033[1;34m"
#define CM         "\033[1;35m"
#define CC         "\033[1;36m"
#define CW         "\033[1;37m"
#define CF         "\033[2m"   // faint
#define CUL        "\033[4m"   // underlined

struct decode *getdecodebyname(const char *name);


#define pletohs(p)	((u_short)                         \
			 ((u_short)*((u_char *)p+1)<<8|    \
			  (u_short)*((u_char *)p+0)<<0))
     
#define pletohl(p)	((u_int32_t)*((u_char *)p+3)<<24|  \
			 (u_int32_t)*((u_char *)p+2)<<16|  \
			 (u_int32_t)*((u_char *)p+1)<<8|   \
			 (u_int32_t)*((u_char *)p+0)<<0)

#define pntohs(p)	((u_short)			   \
			 ((u_short)*((u_char *)p+1)<<0|    \
			  (u_short)*((u_char *)p+0)<<8))
			 
#define pntohl(p)	((u_int32_t)*((u_char *)p+3)<<0|   \
			 (u_int32_t)*((u_char *)p+2)<<8|  \
			 (u_int32_t)*((u_char *)p+1)<<16|  \
			 (u_int32_t)*((u_char *)p+0)<<24)

int	strip_telopts(u_char *buf, int len);

int	strip_lines(char *buf, int max_lines);
void dc_update(struct _dc_meta *m, const void *buf, size_t len);
int	is_ascii_string(char *buf, int len);
u_char * ascii_string(u_char *buf, int sz);
u_char *color_domain(u_char *dst, size_t dsz, u_char *src);
u_char *color_ip(u_char *dst, size_t dsz, in_addr_t ip);

u_char *bufbuf(u_char *big, int blen, u_char *little, int llen);

int	decode_aim(u_char *buf, int len, u_char *obuf, int olen);
int	decode_citrix(u_char *buf, int len, u_char *obuf, int olen);
int	decode_cvs(u_char *buf, int len, u_char *obuf, int olen);
int	decode_ftp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_hex(u_char *buf, int len, u_char *obuf, int olen);
int	decode_http(u_char *buf, int len, u_char *obuf, int olen);
int	decode_icq(u_char *buf, int len, u_char *obuf, int olen);
int	decode_imap(u_char *buf, int len, u_char *obuf, int olen);
int	decode_irc(u_char *buf, int len, u_char *obuf, int olen);
int	decode_ldap(u_char *buf, int len, u_char *obuf, int olen);
int	decode_mmxp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_mountd(u_char *buf, int len, u_char *obuf, int olen);
int	decode_napster(u_char *buf, int len, u_char *obuf, int olen);
int	decode_nntp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_oracle(u_char *buf, int len, u_char *obuf, int olen);
int	decode_ospf(u_char *buf, int len, u_char *obuf, int olen);
int	decode_pcanywhere(u_char *buf, int len, u_char *obuf, int olen);
int	decode_pop(u_char *buf, int len, u_char *obuf, int olen);
int	decode_poppass(u_char *buf, int len, u_char *obuf, int olen);
int	decode_portmap(u_char *buf, int len, u_char *obuf, int olen);
int	decode_postgresql(u_char *buf, int len, u_char *obuf, int olen);
int	decode_pptp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_rip(u_char *buf, int len, u_char *obuf, int olen);
int	decode_rlogin(u_char *buf, int len, u_char *obuf, int olen);
int	decode_smb(u_char *buf, int len, u_char *obuf, int olen);
int	decode_smtp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_sniffer(u_char *buf, int len, u_char *obuf, int olen);
int	decode_snmp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_socks(u_char *buf, int len, u_char *obuf, int olen);
int	decode_tds(u_char *buf, int len, u_char *obuf, int olen);
int	decode_telnet(u_char *buf, int len, u_char *obuf, int olen);
int	decode_vrrp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_x11(u_char *buf, int len, u_char *obuf, int olen);
int	decode_yppasswd(u_char *buf, int len, u_char *obuf, int olen);
int	decode_ypserv(u_char *buf, int len, u_char *obuf, int olen);

int decode_authplain(u_char *p, char **userp, char **passwordp);

#endif /* DECODE_H */
