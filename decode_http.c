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
	char *p, *req, *auth, *pauth, *query, *host, *cookie, *agent, *http_resp = NULL;
	int i;
	int is_sec;
	int is_query_auth;
	int is_http_ok = 1;

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
	if ((dc_meta.rlen > 0) && (p = strtok(dc_meta.rbuf, "\r\n"))) {
		size_t sz = strlen(p);
		if ((sz > 12) && (p[9] != '2'))
			is_http_ok = 0;
		http_resp = p + 9;
	}
	is_sec = 0;
	while ((i = buf_index(&inbuf, "\r\n\r\n", 4)) >= 0) {
		msg = buf_tok(&inbuf, NULL, i);
		msg->base[msg->end] = '\0';
		buf_skip(&inbuf, 4);

		if ((req = strtok(buf_ptr(msg), "\r\n")) == NULL)
			continue;

		if (strncmp(req, "GET ", 4) != 0 &&
		    strncmp(req, "POST ", 5) != 0 &&
		    strncmp(req, "CONNECT ", 8) != 0)
			continue;

		auth = pauth = query = host = cookie = agent = NULL;

		if ((query = strchr(req, '?')) != NULL)
			query++;
		
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
				host = p;
			}
			else if (strncasecmp(p, "Cookie: ", 8) == 0) {
				cookie = p;
				is_sec = 1;
			}
			else if (strncasecmp(p, "User-Agent: ", 12) == 0) {
				agent = p;
			}
			else if (req[0] == 'P') {
				if (strncmp(p, "Content-type: ", 14) == 0) {
					if (strncmp(p + 14, "application/"
						    "x-www-form-urlencoded",
						    33) != 0) {
						query = NULL;
					}
				}
				else if (strncmp(p, "Content-length: ", 16) == 0) {
					p += 16;
					i = atoi(p);
					if ((msg = buf_tok(&inbuf, NULL, i)) == NULL)
						continue;
					msg->base[msg->end] = '\0';
					query = buf_ptr(msg);
				}
			}
		}
		is_query_auth = 0;
		if (query)
			is_query_auth = grep_query_auth(query);
		if (Opt_verbose || cookie || auth || pauth || is_query_auth) {
			if (buf_tell(&outbuf) > 0)
				buf_putf(&outbuf, "\n\n");
			
			if (req[0] == 'G' && auth) {
				req = http_req_dirname(req);
			}

			if (http_resp)
				buf_putf(&outbuf, "%s >>> %s", req, http_resp);
			else
				buf_putf(&outbuf, "%s", req);
			// DUP check up to '?'
			// Anti-Fuzzing: Ignore requests to same host with different 'req' but log if Cookie/Auth is supplied
			// On "-vv" add URI to CRC (and thus log different URIs)
			if ((!Opt_show_dups) && ((is_sec) || (Opt_verbose >= 2)) ) {
				// Only dup-check up to "?"
				if (p = strchr(req, '?'))
					dc_update(&dc_meta, req, p - req);
				else
					dc_update(&dc_meta, req, strlen(req));
			}
			
			if (host) {
				buf_putf(&outbuf, "\n%s", host);
				dc_update(&dc_meta, host + 6, strlen(host + 6));
			}
			if (agent)
				buf_putf(&outbuf, "\n%s", agent);
			if (cookie) {
				buf_putf(&outbuf, "\n%s", cookie);
				// Dont catch 'expires=<>' timer. FIXME: Should really disect the cookie and match for 'expires='
				dc_update(&dc_meta, cookie + 8, MIN(64, strlen(cookie + 8)));
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
			else if (req[0] == 'P' && query) {
				if (is_query_auth)
					dc_update(&dc_meta, "AUTHDUMMY", 1); // XXX HACK to log any POST req. only ONCE.
				buf_putf(&outbuf,
					 "\nContent-type: application/x-www-form-urlencoded\n"
					 "Content-length: %d\n%s",
					 strlen(query), query);
			}
		}
	}
	buf_end(&outbuf);

	// HTTP response was not 2xx. Only log if Cookie/Auth was found.
	if ((!is_http_ok) && (!is_sec))
		return 0;
	
	return (buf_len(&outbuf));
}
