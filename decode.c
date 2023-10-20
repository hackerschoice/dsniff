/*
 * decode.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 * 
 * $Id: decode.c,v 1.13 2001/03/15 08:32:59 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <arpa/telnet.h>
#include <rpc/rpc.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "options.h"
#include "decode.h"
#include "crc32.h"

extern int decode_hex(u_char *, int, u_char *, int);
extern int decode_ftp(u_char *, int, u_char *, int);
extern int decode_ssh(u_char *, int, u_char *, int);
extern int decode_telnet(u_char *, int, u_char *, int);
extern int decode_smtp(u_char *, int, u_char *, int);
extern int decode_pptp(u_char *, int, u_char *, int);
extern int decode_http(u_char *, int, u_char *, int);
extern int decode_ospf(u_char *, int, u_char *, int);
extern int decode_poppass(u_char *, int, u_char *, int);
extern int decode_pop(u_char *, int, u_char *, int);
extern int decode_nntp(u_char *, int, u_char *, int);
extern int decode_smb(u_char *, int, u_char *, int);
extern int decode_imap(u_char *, int, u_char *, int);
extern int decode_snmp(u_char *, int, u_char *, int);
extern int decode_ldap(u_char *, int, u_char *, int);
extern int decode_mmxp(u_char *, int, u_char *, int);
extern int decode_sni(u_char *, int, u_char *, int);
extern int decode_rlogin(u_char *, int, u_char *, int);
extern int decode_rip(u_char *, int, u_char *, int);
extern int decode_socks(u_char *, int, u_char *, int);
extern int decode_citrix(u_char *, int, u_char *, int);
extern int decode_oracle(u_char *, int, u_char *, int);
extern int decode_tds(u_char *, int, u_char *, int);
extern int decode_sniffer(u_char *, int, u_char *, int);
extern int decode_cvs(u_char *, int, u_char *, int);
extern int decode_icq(u_char *, int, u_char *, int);
extern int decode_napster(u_char *, int, u_char *, int);
extern int decode_aim(u_char *, int, u_char *, int);
extern int decode_postgresql(u_char *, int, u_char *, int);
extern int decode_pcanywhere(u_char *, int, u_char *, int);
extern int decode_x11(u_char *, int, u_char *, int);
extern int decode_irc(u_char *, int, u_char *, int);
extern int decode_portmap(u_char *, int, u_char *, int);
extern int decode_mountd(u_char *, int, u_char *, int);
extern int decode_vrrp(u_char *, int, u_char *, int);
extern int decode_ypserv(u_char *, int, u_char *, int);
extern int decode_yppasswd(u_char *, int, u_char *, int);

static struct decode decodes[] = {
	{ "hex",	decode_hex },
	{ "ftp",	decode_ftp },
	{ "ssh",    decode_ssh },
	{ "telnet",	decode_telnet },
	{ "smtp",	decode_smtp },
	{ "pptp",	decode_pptp },
	{ "http",	decode_http },
	{ "ospf",	decode_ospf },
	{ "poppass",	decode_poppass },
	{ "pop2",	decode_pop },
	{ "pop3",	decode_pop },
	{ "nntp",	decode_nntp },
	{ "smb",	decode_smb },
	{ "imap",	decode_imap },
	{ "snmp",	decode_snmp },
	{ "ldap",	decode_ldap },
	{ "mmxp",	decode_mmxp },
	{ "https",  decode_sni },
	{ "rlogin",	decode_rlogin },
	{ "rip",	decode_rip },
	{ "socks",	decode_socks },
	{ "citrix",	decode_citrix },
	{ "oracle",	decode_oracle },
	{ "tds",	decode_tds },
	{ "sniffer",	decode_sniffer },
	{ "cvs",	decode_cvs },
	{ "icq",	decode_icq },
	{ "napster",	decode_napster },
	{ "aim",	decode_aim },
	{ "postgresql",	decode_postgresql },
	{ "pcanywhere", decode_pcanywhere },
	{ "vrrp",	decode_vrrp },
	{ "x11",	decode_x11 },
	{ "irc",	decode_irc },
	{ "portmap",	decode_portmap },
	{ "mountd",	decode_mountd },
	{ "ypserv",	decode_ypserv },
	{ "yppasswd",	decode_yppasswd },
	{ NULL }
};

struct _dc_meta dc_meta; // Globally shared.

void
dc_update(struct _dc_meta *m, const void *buf, size_t len) {
	if (Opt_show_dups)
		return;
	m->crc = crc32_update(buf, len, m->crc);
}

struct decode *
getdecodebyname(const char *name)
{
	struct decode *dc;
	
	for (dc = decodes; dc->dc_name != NULL; dc++) {
		if (strcasecmp(dc->dc_name, name) == 0)
			return (dc);
	}
	return (NULL);
}

/* Strip telnet options, as well as suboption data. */
int
strip_telopts(u_char *buf, int len)
{
	int i, j, subopt = 0;
	char *p, *q;
	
	for (i = j = 0; i < len; i++) {
		if (buf[i] == IAC) {
			if (++i >= len) break;
			else if (buf[i] > SB)
				i++;
			else if (buf[i] == SB) {
				/* XXX - check for autologin username. */
				p = buf + i + 1;
				if ((q = bufbuf(p, len - i, "\xff", 1))
				    != NULL) {
					if ((p = bufbuf(p, q - p, "USER\x01",
							5)) != NULL) {
						p += 5;
						buf[j++] = '[';
						memcpy(buf + j, p, q - p);
						j += q - p;
						buf[j++] = ']';
						buf[j++] = '\n';
					}
				}
				subopt = 1;
			}
			else if (buf[i] == SE) {
				if (!subopt) j = 0;
				subopt = 0;
			}
		}
		else if (!subopt) {
			/* XXX - convert isolated returns to newlines. */
			if (buf[i] == '\r' && i + 1 < len &&
			    buf[i + 1] != '\n')
				buf[j++] = '\n';
			/* XXX - strip binary nulls. */
			else if (buf[i] != '\0')
				buf[j++] = buf[i];
		}
	}
	buf[j] = '\0';
	
	return (j);
}

/* Strip a string buffer down to a maximum number of lines. */
int
strip_lines(char *buf, int max_lines)
{
	char *p;
	int lines, nonascii;
	
	if (!buf) return (0);
	
	lines = nonascii = 0;
	
	for (p = buf; *p && lines < max_lines; p++) {
		if (*p == '\n') lines++;
		if (!isascii(*p)) nonascii++;
	}
	if (*p) *p = '\0';
	
	/* XXX - lame ciphertext heuristic */
	if (nonascii * 3 > p - buf)
		return (0);
	
	return (lines);
}

int
is_ascii_string(char *buf, int len)
{
	int i;
	
	for (i = 0; i < len; i++)
		if (!isascii(buf[i])) return (0);
	
	return (1);
}

u_char *
bufbuf(u_char *big, int blen, u_char *little, int llen)
{
	u_char *p;
	
         for (p = big; p <= big + blen - llen; p++) {
		 if (memcmp(p, little, llen) == 0)
			 return (p);
	 }
	 return (NULL);
}

// WARNING: sz must be >= 1
u_char *
ascii_string(u_char *buf, int sz) {
	u_char *end = buf + sz;
	u_char *ptr = buf;

	while (ptr < end) {
		if (*ptr == 0x0d)
			break;
		if (*ptr == 0x0a)
			break;
		if (*ptr == 0x00)
			break;
		if (!isascii(*ptr)) {
			*ptr = '?';
		}
		ptr++;
	}
	if (ptr >= end)
		ptr--;
	if (*ptr != 0x00)
		*ptr = '\0';

	return buf;
}

u_char *
color_domain(u_char *dst, size_t dsz, u_char *src) {
	int n = 0;
	u_char *end = src + strlen(src);
	int is_ip = 1;

	while ((n < 2) && (src < end--)) {
		if (*end == '.') {
			n++;
			continue;
		}
		if (!isdigit(*end))
			is_ip = 0;
	}

	if ((!is_ip) && (n >= 2)) {
		*end = '\0';
		snprintf(dst, dsz, CM "%s"CDM ".%s"CN, src, end + 1);
		// snprintf(dst, dsz, CM CUL"%s"CDM CUL".%s"CN, src, end + 1);
	} else
		snprintf(dst, dsz, CDM "%s"CN, src);
		// snprintf(dst, dsz, CDM CUL"%s"CN, src);

	return dst;
}

struct _ip_colors {
	char *pre;
	char *mid;
	char *suf;
};

struct _ip_colors ipcol[] = {
	{CDC, CC CF, CN CC},
	{CDR, CR CF, CN CR},
	{CDG, CG CF, CN CG},
	{CDB, CB CF, CN CB},
	{CDY, CY CF, CN CY},
	{CDM, CM CF, CN CM}
};

#ifndef int_ntoa
# define int_ntoa(x)    inet_ntoa(*((struct in_addr *)&x))
#endif

// Assign a random color scheme to an IP.
u_char *
color_ip(u_char *dst, size_t dsz, in_addr_t ip) {
	char *pre, *suf, *mid;
	char *src = int_ntoa(ip);
	char *end = src + strlen(src);
	char *pos[3];
	int n = 3;

	while ((n > 0) && (src < end--)) {
		if (*end != '.')
			continue;

		pos[--n] = end;
	}
	if (n > 0) {
		// Not '3' dots. Not an IPv4
		snprintf(dst, dsz, "%d %s", n, src);
		return dst;
	}

	// Pick color by /24 
	struct _ip_colors *ipc = &ipcol[crc32(&ip, 3) % (sizeof ipcol / sizeof *ipcol)];

	*pos[0] = *pos[2] = '\0';
	snprintf(dst, dsz, "%s%s.%s%s.%s%s"CN, ipc->pre, src, ipc->mid, pos[0] + 1, ipc->suf, pos[2] + 1);

	return dst;
}

