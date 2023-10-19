/*
 * decode_pop.c
 *
 * Post Office Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_pop.c,v 1.4 2001/03/15 08:33:02 dugsong Exp $
 *
 * Rewritten by Stefan Tomanek 2011 <stefan@pico.ruhr.de>
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <strlcat.h>

#include "base64.h"
#include "options.h"
#include "decode.h"

int
decode_poppass(u_char *buf, int len, u_char *obuf, int olen)
{
	char *p;
	
	obuf[0] = '\0';
	
	for (p = strtok(buf, "\r\n"); p != NULL; p = strtok(NULL, "\r\n")) {
		if (strncasecmp(p, "user ", 5) == 0 ||
		    strncasecmp(p, "pass ", 5) == 0 ||
		    strncasecmp(p, "newpass ", 8) == 0) {
			strlcat(obuf, p, olen);
			strlcat(obuf, "\n", olen);
		}
	}
	if (strip_lines(obuf, Opt_lines) < 3)
		return (0);
	
	return (strlen(obuf));
}

int
decode_pop(u_char *buf, int len, u_char *obuf, int olen)
{
	char *p;
	char *s;
	int n;
	int i, j;
	char *user;
	char *password;
	enum {
		NONE,
		AUTHPLAIN,
		AUTHLOGIN,
		USERPASS
	} mode = NONE;

	
	obuf[0] = '\0';
	
	for (p = strtok(buf, "\r\n"); p != NULL; p = strtok(NULL, "\r\n")) {
		if (mode == NONE) {
			user = NULL;
			password = NULL;
			if (strncasecmp(p, "AUTH PLAIN", 10) == 0) {
				mode = AUTHPLAIN;
				continue;
			}
			if (strncasecmp(p, "AUTH LOGIN", 10) == 0) {
				mode = AUTHLOGIN;
				continue;
			}
			if (strncasecmp(p, "USER ", 5) == 0) {
				mode = USERPASS;
				/* the traditional login cuts right to the case,
				 * so no continue here
				 */
			}
		}
		printf("(%d) %s\n", mode, p);
		if (mode == USERPASS) {
			if (strncasecmp(p, "USER ", 5) == 0) {
				user = &p[5];
			} else if (strncasecmp(p, "PASS ", 5) == 0) {
				password = &p[5];
			}
		}

		if (mode == AUTHPLAIN) {
			j = base64_pton(p, p, strlen(p));
			p[j] = '\0';
			n = 0;
			s = p;
			/* p consists of three parts, divided by \0 */
			while (s <= &p[j] && n<=3) {
				if (n == 0) {
					/* we do not process this portion yet */
				} else if (n == 1) {
					user = s;
				} else if (n == 2) {
					password = s;
				}
				n++;
				while (*s) s++;
				s++;
			}
		}

		if (mode == AUTHLOGIN) {
			j = base64_pton(p, p, strlen(p));
			p[j] = '\0';
			if (! user) {
				user = p;
			} else {
				password = p;
				/* got everything we need :-) */
			}
		}

		if (user && password) {
			strlcat(obuf, "\nusername [", olen);
			strlcat(obuf, user, olen);
			strlcat(obuf, "] password [", olen);
			strlcat(obuf, password, olen);
			strlcat(obuf, "]\n", olen);

			mode = NONE;
		}
	}
	return (strlen(obuf));
}

