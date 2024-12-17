/*
 * decode_http.c
 *
 * Hypertext Transfer Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_http.c,v 1.17 2001/03/15 08:32:59 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <regex.h>
#include <libgen.h>
#include <err.h>

#include "options.h"
#include "base64.h"
#include "buf.h"
#include "decode.h"
#include "crc32.h"

#define USER_REGEX	".*account.*|.*acct.*|.*domain.*|.*login.*|" \
			".*member.*|.*user.*|.*name|.*email|.*_id|" \
			"id|uid|mn|mailaddress"
			
#define PASS_REGEX	".*pass.*|.*pw|pw.*|additional_info"

#define REGEX_FLAGS	(REG_EXTENDED | REG_ICASE | REG_NOSUB)

static regex_t		*user_regex, *pass_regex;

extern struct _dc_meta dc_meta;

static int
grep_query_auth(char *buf)
{
	char *p, *q, *tmp;
	int user, pass;

	user = pass = 0;
	
	if ((tmp = strdup(buf)) == NULL)
		return (0);
	
	for (p = strtok(tmp, "&"); p != NULL; p = strtok(NULL, "&")) {
		if ((q = strchr(p, '=')) == NULL)
			continue;
		*q = '\0';
			
		if (!user) {
			if (regexec(user_regex, p, 0, NULL, 0) == 0) {
				user = 1;
				continue;
			}
		}
		if (!pass) {
			if (regexec(pass_regex, p, 0, NULL, 0) == 0)
				pass = 1;
		}
		if (user && pass) break;
	}
	free(tmp);
	
	return (user && pass);
}

// Used for AUTH requests only (directories, not files, are authorized)
static char *
http_req_dirname(char *req)
{
	char *uri, *vers;
	
	if ((uri = strchr(req, ' ')) == NULL)
		return (req);
	
	if ((vers = strrchr(uri, ' ')) == uri) {
		vers = NULL;  // "GET /file"
	} else if (vers[-1] == '/') {
		return (req); // "GET /file/ HTTP/1.1"
	} else
		*vers++ = '\0'; // "GET /file HTTP/1.1"
	
	strcpy(req, dirname(req));
	strcat(req, "/");
	
	if (vers) {
		strcat(req, " ");
		strcat(req, vers);
	}
	return (req);
}  

int
decode_http(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *msg, inbuf, outbuf;
	char *p, *req, *auth, *pauth, *gquery, *query, *host, *cookie, *agent, *location = NULL, *http_resp = NULL;
	int i;
	int is_sec;
	int is_query_auth;
	int is_http_ok = 1; // default assume OK
	char dom[1024];
	char *type;
	char *uri_prot;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);

	if (user_regex == NULL || pass_regex == NULL) {
		if ((user_regex = malloc(sizeof(*user_regex))) == NULL ||
		    (pass_regex = malloc(sizeof(*pass_regex))) == NULL)
			err(1, "malloc");
		
		if (regcomp(user_regex, USER_REGEX, REGEX_FLAGS) ||
		    regcomp(pass_regex, PASS_REGEX, REGEX_FLAGS))
			errx(1, "regcomp failed");
	}
	is_sec = 0;
	if ((dc_meta.rbuf) && (p = strtok(dc_meta.rbuf, "\r\n")) && (strlen(p) > 12)) {
		http_resp = p + 9;
		if (p[9] != '2')
			is_http_ok = 0;
		if (p[9] == '3') {
			while ((p = strtok(NULL, "\r\n")) != NULL) {
				if (strncasecmp(p, "Location: ", 10) != 0)
					continue;

				location = p + 10;
				if (strstr(location, "https://"))
					is_sec = 1; // http -> https redirects can be intercepted.
				break;
			}
		}
	}
	while ((i = buf_index(&inbuf, "\r\n\r\n", 4)) >= 0) {
		msg = buf_tok(&inbuf, NULL, i);
		msg->base[msg->end] = '\0';
		buf_skip(&inbuf, 4);

		if ((req = strtok(buf_ptr(msg), "\r\n")) == NULL)
			continue;

		if (strncmp(req, "GET ", 4) == 0) {
			type = "GET"; uri_prot = req + 4; 
		} else if (strncmp(req, "POST ", 5) == 0) {
			type = "POST"; uri_prot = req + 5;
		} else if (strncmp(req, "CONNECT ", 8) == 0) {
			type = "CONNECT"; uri_prot = req + 8;
		} else
			continue;

		auth = pauth = query = host = cookie = agent = NULL;

		if ((query = strchr(uri_prot, '?')) != NULL) {
			query++;
			gquery = query;
		}

		while ((p = strtok(NULL, "\r\n")) != NULL) {
			if (strncasecmp(p, "Authorization: Basic ", 21) == 0) {
				auth = p;
				is_sec = 1;
			}				
			else if (strncasecmp(p, "Proxy-authorization: Basic ", 27) == 0) {
				pauth = p;
				is_sec = 1;
			}
			else if (strncasecmp(p, "Host: ", 6) == 0) {
				host = p + 6;
			}
			else if (strncasecmp(p, "Cookie: ", 8) == 0) {
				cookie = p + 8;
				is_sec = 1;
			}
			else if (strncasecmp(p, "User-Agent: ", 12) == 0) {
				agent = p;
			}
			else if (type[0] == 'P') {
				if (strncasecmp(p, "Content-type: ", 14) == 0) {
					if (strncmp(p + 14, "application/"
						    "x-www-form-urlencoded",
						    33) != 0) {
						query = NULL;
					}
				}
				else if (strncasecmp(p, "Content-length: ", 16) == 0) {
					p += 16;
					i = atoi(p);
					if ((msg = buf_tok(&inbuf, NULL, i)) == NULL)
						continue;
					msg->base[msg->end] = '\0';
					query = buf_ptr(msg);
				}
			}
		} // while()

		is_query_auth = 0;
		if (query) {
			is_query_auth = grep_query_auth(query);
			if (is_query_auth)
				is_sec = 1;
		}
		if (Opt_verbose || cookie || auth || pauth || is_query_auth) {
			if (buf_tell(&outbuf) > 0)
				buf_putf(&outbuf, "\n\n");
			
			if (type[0] == 'G' && auth) {
				req = http_req_dirname(req);
			}

			if (Opt_color) {
				if (gquery) {
					*(gquery - 1) = '\0';
					buf_putf(&outbuf, CB"%s"CDC" %s"CN"?%s", type, uri_prot, gquery);
					*(gquery -1) = '?';
				} else {
					if (p = strchr(uri_prot, ' ')) {
						*p = '\0';
						buf_putf(&outbuf, CB"%s"CDC" %s"CN" %s", type, uri_prot, p+1);
						*p = ' ';
					} else
						buf_putf(&outbuf, CB"%s"CDC" %s"CN, type, uri_prot);
				}
			} else
				buf_putf(&outbuf, "%s", req);

			if (http_resp)
				buf_putf(&outbuf, " >>> %s", http_resp);
			if (is_sec) 
				dc_meta.is_hot = 1;
			
			// DUP check up to '?'
			// Anti-Fuzzing: Ignore requests to same host with different 'req' but log if Cookie/Auth is supplied
			// On "-vv" add URI to CRC (and thus log different URIs)
			if ((!Opt_show_dups) && (is_http_ok) && ((is_sec) || (Opt_verbose >= 2)) ) {
				// Only dup-check up to "?"
				if (gquery)
					dc_update(&dc_meta, req, gquery - 1 - req);
				else
					dc_update(&dc_meta, req, strlen(req));
			}
			
			if (host) {
				if (Opt_color)
					buf_putf(&outbuf, "\n"CDY"Host"CN": %s", color_domain(dom, sizeof dom, host));
				else
					buf_putf(&outbuf, "\nHost: %s", host);

				dc_update(&dc_meta, host, strlen(host));
			}

			if (location) {
				if (Opt_color)
					buf_putf(&outbuf, "\n"CDY"Location"CN": "CDR"%s"CN, location);
				else
					buf_putf(&outbuf, "\nLocation: %s", location);
				location = NULL;
				break; // Stop on LOCATION reply.
			}

			if (agent)
				buf_putf(&outbuf, "\n%s", agent);
			if (cookie) {
				if (Opt_color)
					buf_putf(&outbuf, "\n"CDR"Cookie"CN": %s", cookie);
				else
					buf_putf(&outbuf, "\nCookie: %s", cookie);
				// Dont catch 'expires=<>' timer (limit to 64). FIXME: Should really disect the cookie and match for 'expires='
				// Prevent Fuzzing from flooding our log => Use max of 19 dubdb-slots
				if (!Opt_show_dups) {
					uint8_t fuzz = crc32(cookie, MIN(64, strlen(cookie))) % 19;
					dc_update(&dc_meta, &fuzz, 1);
				}
			}
			if (pauth) {
				buf_putf(&outbuf, "\n%s", pauth);
				dc_update(&dc_meta, pauth + 27, strlen(pauth + 27));
				p = pauth + 27;
				i = base64_pton(p, p, strlen(p));
				p[i] = '\0';
				buf_putf(&outbuf, " [%s]", p);
			}

			if (auth) {
				buf_putf(&outbuf, "\n%s", auth);
				dc_update(&dc_meta, auth + 21, strlen(auth + 21));
				p = auth + 21;
				i = base64_pton(p, p, strlen(p));
				p[i] = '\0';
				buf_putf(&outbuf, " [%s]", p);
			}
			else if (type[0] == 'P' && query && query != gquery) {
				if (is_query_auth)
					dc_update(&dc_meta, "AUTHDUMMY", 1); // XXX HACK to log any POST req. only ONCE.

				p = query;
				char *n;
				while ((n = strchr(p, '&'))) {
					*n = '\0';
					buf_putf(&outbuf, "\n%s", p);
					p = n + 1;
				}
				buf_putf(&outbuf, "\n%s", p);
			}
		}
	} //while ((i = buf_index(&inbuf, "\r\n\r\n", 4)) >= 0) 
	buf_end(&outbuf);

	// HTTP response was not 2xx. Only log if Cookie/Auth was found.
	if ((!is_http_ok) && (!is_sec))
		return 0;
	
	return (buf_len(&outbuf));
}
