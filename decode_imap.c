/*
 * decode_imap.c
 *
 * Internet Mail Access Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_imap.c,v 1.5 2001/03/15 08:33:00 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "decode.h"
#include "buf.h"

extern struct _dc_meta dc_meta;

int
decode_imap(u_char *buf, int len, u_char *obuf, int olen)
{
	char *p;
	char *ptr;
	int need_more = 0;
	enum {
		NONE,
		AUTHPLAIN,
		AUTHMULTI,
		USERPASS
	} mode = NONE;

	obuf[0] = '\0';

	for (p = strtok(buf, "\r\n"); p != NULL; p = strtok(NULL, "\r\n")) {
		if (need_more == 0) {
			// skip ID
			if ((ptr = strchr(p, ' ')) == NULL)
				break;
			p = ++ptr;
		}

		if (mode == NONE) {
			if (strncasecmp(p, "AUTHENTICATE PLAIN", 18) == 0) {
				mode = AUTHPLAIN;
				need_more = 1;
				continue;
			} else if ((strncasecmp(p, "AUTHENTICATE ", 13) == 0) || (strncasecmp(p, "LOGIN {", 6) == 0)) {
				strlcat(obuf, p, olen);
				mode = AUTHMULTI;
				need_more = 2;
				continue;
			} else if (strncasecmp(p, "LOGIN ", 6) == 0) {
				mode = USERPASS; // FALL-THROUGH.
			} else 
				continue;
		}

		if (mode == USERPASS) {
			snprintf(obuf, olen, "%s\n", p + 6 /* 'LOGIN '*/);
			break;
		}

		if (mode == AUTHPLAIN) {
			char *u , *pass;
			if (decode_authplain(p, &u, &pass) != 0)
				break;
			snprintf(obuf, olen, "%s %s\n", u, pass);
			break;
		}

		if (need_more > 0) {
			need_more--;
			strlcat(obuf, p, olen);
			if (need_more > 0)
				continue;
			strlcat(obuf, "\n", olen);
			break;
		}
		break;
	}

	if (obuf[0] == '\0')
		return 0;

	dc_meta.is_hot = 1;
	return (strlen(obuf));
}
