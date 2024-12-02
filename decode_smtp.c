/*
 * decode_smtp.c
 *
 * Simple Mail Transfer Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_smtp.c,v 1.3 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <strlcat.h>

#include "base64.h"
#include "options.h"
#include "decode.h"

extern struct _dc_meta dc_meta;

int
decode_smtp(u_char *buf, int len, u_char *obuf, int olen)
{
	char *p, *s;
	int i, j, login = 0;
	int found = 0;
	
	obuf[0] = '\0';
	for (p = strtok(buf, "\r\n"); p != NULL; p = strtok(NULL, "\r\n")) {
		if ((strncmp(p, "MAIL ", 5) == 0) || (strncmp(p, "RCPT ", 5) == 0)) {
			if (!Opt_verbose)
				break;
			if (obuf[0] != '\0')
				strlcat(obuf, "\n", olen);
			strlcat(obuf, p+5, olen);
			if (++found >= 2)
				break;
			continue;
		}
		if ((strncmp(p, "DATA", 4) == 0) || (strncmp(p, "QUIT", 4) == 0))
			break;

		if (login == 0) {
			if (strncmp(p, "AUTH LOGIN", 10) != 0)
				continue;
		
			strlcat(obuf, p, olen);
			p += 10;
			i = base64_pton(p, p, strlen(p));
			if (i > 0) {
				p[i] = '\0';
				j = strlen(obuf);
				snprintf(obuf + j, olen - j, " [%s]", p);
			} else {
				strlcat(obuf, " ", olen);
				login = 1;
			}
			dc_meta.is_hot = 1;
			continue;
		}

		strlcat(obuf, p, olen);
		// USER: <base64>
		// PASS: <base64>
		// <base64>
		if ((s = strchr(p, ' ')) != NULL)
			p = ++s;
		i = base64_pton(p, p, strlen(p));
		if (i > 0) {
			p[i] = '\0';
			j = strlen(obuf);
			snprintf(obuf + j, olen - j, " [%s] ", p);
		}
	}
	return (strlen(obuf));
}
