/*
 * decode_http.c
 *
 * Hypertext Transfer Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_http.c,v 1.17 2001/03/15 08:32:59 dugsong Exp $
 */

#include "common.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <regex.h>
#include <libgen.h>
#include <err.h>

#include "options.h"
#include "base64.h"
#include "buf.h"
#include "decode.h"
#include "crc32.h"

#define USER_REGEX	"account|acct|domain|login|" \
			"member|user|name|email|_id|" \
			"id|uid|mn|mailaddress"
			
#define PASS_REGEX	"pass|pw|additional_info"

#define HOTS_REGEX	"bearer|pass|token|auth"

#define REGEX_FLAGS	(REG_EXTENDED | REG_ICASE | REG_NOSUB)

static regex_t		*user_regex, *pass_regex, *hots_regex;

extern struct _dc_meta dc_meta;

/* Pre-initialized lookup table for hex digit values (returns '*' if not hex) */
static const unsigned char hex_table[256] = {
    /* 0..15 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 16..31 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 32..47 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 48..63  '0'..'9' at 48..57 */
    0,1,2,3,4,5,6,7,8,9,'*','*','*','*','*','*',
    /* 64..79  'A'..'F' at 65..70 */
    '*',10,11,12,13,14,15,'*','*','*','*','*','*','*','*','*',
    /* 80..95 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 96..111 'a'..'f' at 97..102 */
    '*',10,11,12,13,14,15,'*','*','*','*','*','*','*','*','*',
    /* 112..127 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 128..143 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 144..159 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 160..175 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 176..191 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 192..207 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 208..223 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 224..239 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*',
    /* 240..255 */
    '*','*','*','*','*','*','*','*','*','*','*','*','*','*','*','*'
};

/* In-place URL-decode: converts "%xx" -> byte and '+' -> ' ' directly in the input buffer.
 * The decoded result overwrites the original string.
 */
static char *
url_decode_inplace(char *s, int is_decode_plus) {
    if (!s)
		return NULL;

    char *r = s, *w = s;

    while (*r) {
        if (*r == '%' && r[1] != '\0' && r[2] != '\0') {
            unsigned char hi = hex_table[(unsigned char)r[1]];
            unsigned char lo = hex_table[(unsigned char)r[2]];
            if (hi != '*' && lo != '*') {
                *w++ = (char)((hi << 4) | lo);
                r += 3;
                continue;
            }
            /* not valid hex, fall through to copy '%' literally */
        }
        if ((*r == '+') && (is_decode_plus)) {
            *w++ = ' ';
        } else {
            *w++ = *r;
        }
        r++;
    }
    *w = '\0';
    return s;
}

static int
grep_pquery_hots(char *buf) {
	if (buf == NULL)
		return 0;
	if (regexec(hots_regex, buf, 0, NULL, 0) == 0)
		return 1; // HOT

	return 0;
}

// Return if form-data contains a user _AND_ a password
static int
grep_gquery_auth(char *buf)
{
	char *p, *q, *tmp;
	int user, pass;

	if (buf == NULL)
		return 0;
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

#define BUF_FORM_FL_IS_HOT	    0x01
#define BUF_FORM_FL_DO_DECODE	0x02
#define BUF_FORM_FL_SKIP_SINGLE 0x04 // skip output if there is only a single key=value pair
#define BUF_FORM_FL_DECODE_PLUS	0x08 // decode '+' to space
#define BUF_FORM_FL_NO_COLOR	0x10
// Display decoded variables
static void
buf_hot_form(struct buf *o, char *p, char delim, int flag) {
	char *dc;
	char *n;
	int is_color = (Opt_color && !(flag & BUF_FORM_FL_NO_COLOR));

	if (!p)
		return;

	// Check if we should skip single key=value pairs
	if (flag & BUF_FORM_FL_SKIP_SINGLE) {
		n = strchr(p, delim);
		if (!n)
			return; // single variable
		if (*(n + 1) == '\0')
			return; // ';' present but no further variables thereafter.
	}

	if (is_color) {
		if (flag & BUF_FORM_FL_IS_HOT)
			buf_put(o, CDR, sizeof CDR - 1);
		else
			buf_put(o, CDY CF, sizeof CDY - 1 + sizeof CF - 1);
	}
	while ((n = strchr(p, delim))) {
		*n = '\0';
		dc = p;
		if (flag & BUF_FORM_FL_DO_DECODE)
			dc = url_decode_inplace(p, flag & BUF_FORM_FL_DECODE_PLUS);
		buf_putf(o, "\n%s", dc);
		p = n + 1;
		while (*p == ' ')
			p++; // Remove cookie space after ';'
	}
	if (*p)
		buf_putf(o, "\n%s", p); // remainder

	if (is_color)
		buf_put(o, CN, sizeof CN - 1);
}

static void
buf_hot_header(struct buf *o, char *p) {
	char *col;
	if (!p)
		return;
	dc_update(&dc_meta, p, strlen(p));

	if (Opt_color) {
		col = strchr(p, ':');
		*col = '\0';
		buf_putf(o, "\n"CDY"%s:"CDR"%s"CN, p, col + 1);
		*col = ':';
	} else
		buf_putf(o, "\n%s", p);
}

#define DS_PAYLOAD_MAX_OUT             (1024)
static void
buf_hot(struct buf *o, char *p, int len, int is_hot) {
	if (!p)
		return;

	if (len <= 0)
		return;

	// Check if printable..
	char *ip = p;
	// char *endp = p + MIN(len, 10); # Check first 10 characters only
	char *endp = p + len;
	while (ip < endp && isprint(*ip))
		ip++;

	if (ip < endp) {
		// Not printable
		if (Opt_color)
			buf_putf(o, "\n"CDY""CF);
		else
			buf_put(o, "\n", 1);
		buf_put_hex(o, p, MIN(len, DS_PAYLOAD_MAX_OUT / 4), 0);
		if (len > DS_PAYLOAD_MAX_OUT / 4)
			buf_putf(o, "  <...%d bytes omitted...>", len - DS_PAYLOAD_MAX_OUT / 4);
		if (Opt_color)
			buf_put(o, CN, sizeof CN - 1);
		return;
	}
	if (is_hot && Opt_color) {
		buf_putf(o, "\n"CDR"%s"CN, p);
	} else if (Opt_color) {
		buf_putf(o, "\n"CDY""CF"%s"CN, p);
	} else
		buf_putf(o, "\n%s", p);
}

int
decode_http(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *msg, inbuf, outbuf;
	char *p, *req, *key, *bearer, *auth, *pauth, *gquery, *pquery, *host, *cookie, *agent, *location = NULL, *http_resp = NULL;
	int i;
	int is_http_ok = 1; // default assume OK
	int is_unauthorized = 0;
	char dom[1024];
	char *type;
	char *uri_prot;
	int is_location_hot = 0;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);

	if (user_regex == NULL || pass_regex == NULL || hots_regex == NULL) {
		if ((user_regex = malloc(sizeof(*user_regex))) == NULL ||
		    (pass_regex = malloc(sizeof(*pass_regex))) == NULL ||
		    (hots_regex = malloc(sizeof(*hots_regex))) == NULL)

			err(1, "malloc");
		
		if (regcomp(user_regex, USER_REGEX, REGEX_FLAGS) ||
		    regcomp(pass_regex, PASS_REGEX, REGEX_FLAGS) ||
		    regcomp(hots_regex, HOTS_REGEX, REGEX_FLAGS))
			errx(1, "regcomp failed");
	}

	// Check SERVER's answer
	if ((dc_meta.rbuf) && (p = strtok(dc_meta.rbuf, "\r\n")) && (strlen(p) > 12)) {
		http_resp = p + 9;
		if (p[9] != '2')
			is_http_ok = 0;
		if (p[9] == '3') {
			while ((p = strtok(NULL, "\r\n")) != NULL) {
				if (strncasecmp(p, "Location: ", 10) != 0)
					continue;
				if (strstr(p + 10, "https://") != NULL) {
					location = p + 10; //url_decode_inplace(p + 10, 0);
					is_location_hot = 1; // http -> https redirects can be intercepted.
				}
				break;
			}
		} else if (p[9] == '4' && p[10] == '0' && p[11] == '1')
			is_unauthorized = 1;
	}

	// Parse CLIENT's submission
	while ((i = buf_index(&inbuf, "\r\n\r\n", 4)) >= 0) {
		int is_json = 0;
		int is_form = 0;
		int cont_len = 0;
		int is_hot = 0;
		int is_gquery_hot = 0;
		int is_pquery_hot = 0;
		int is_chunked = 0;

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

		// uri_prot = url_decode_inplace(uri_prot);

		key = bearer = auth = pauth = gquery = pquery = host = cookie = agent = NULL;

		if ((gquery = strchr(uri_prot, '?')) != NULL)
			gquery++;

		char *colon;
		while ((p = strtok(NULL, "\r\n")) != NULL) {
			colon = strchr(p, ':');
			if (!colon)
				continue;
			
			// Check for X-API-Key: etc
			*colon = '\0';
			if (strcasestr(p, "key")) {
				key = p;
				is_hot = 1;
			}
			*colon = ':';

			if (strncasecmp(p, "Authorization: Basic ", 21) == 0) {
				auth = p;
				is_hot = 1;
			}
			else if (strncasecmp(p, "Authorization: Bearer ", 22) == 0) {
				bearer = p;
				is_hot = 1;
			}
			else if (strncasecmp(p, "Proxy-authorization: Basic ", 27) == 0) {
				pauth = p;
				is_hot = 1;
			}
			else if (strncasecmp(p, "Host: ", 6) == 0) {
				host = p + 6;
			}
			else if (strncasecmp(p, "Cookie: ", 8) == 0) {
				cookie = p + 8;
				// Cookies are always "hot" unless it's a 401 Unauthorized response
				if (!is_unauthorized)
					is_hot = 1;
			}
			else if (strncasecmp(p, "Transfer-encoding: chunked", 23) == 0) {
				is_chunked = 1;
			}
			else if (strncasecmp(p, "User-Agent: ", 12) == 0) {
				agent = p;
			}
			else if (type[0] == 'P') {
				// POST
				if (strncasecmp(p, "Content-type: ", 14) == 0) {
					if (strncmp(p + 14, "application/x-www-form-urlencoded", 33) == 0)
						is_form = 1;
					else if (strncmp(p + 14, "application/json", 16) == 0)
						is_json = 1;
				}
				else if (strncasecmp(p, "Content-length: ", 16) == 0) {
					p += 16;
					cont_len = atoi(p);
				}
			}
		} // while()
		// HERE: Header done.
		if (is_chunked) {
			char *endptr;
			// Only support first chunk for now.
			while (1) {
				// Read chunk size line
				if ((i = buf_index(&inbuf, "\r\n", 2)) < 0)
					break; // incomplete
				msg = buf_tok(&inbuf, NULL, i);
				msg->base[msg->end] = '\0';
				buf_skip(&inbuf, 2);
				cont_len = (int)strtol(buf_ptr(msg), &endptr, 16);
				break;
			}
		}
		if (cont_len > 0) {
			if ((msg = buf_tok(&inbuf, NULL, cont_len)) != NULL) {
				msg->base[msg->end] = '\0';
				pquery = buf_ptr(msg);
				cont_len = MIN(cont_len, msg->end); // in case cont_len was longer than sniffed data.
				// Telegram web sends "Content-Type: application/x-www-form-urlencoded"
				// followed by binary data (not url-encoded). 
			} else
				cont_len = 0;
		}

		// Check if queries contain keywords ['password' etc]
		if (grep_gquery_auth(gquery))
			is_gquery_hot++;
		if (grep_pquery_hots(pquery))
			is_pquery_hot++;
		is_hot += (is_gquery_hot + is_pquery_hot + is_location_hot);

		if (!(Opt_verbose || is_hot))
			continue; // Nothing to log. Next header.

		// HERE: Got header data. Start populating output buffer.
		// If multiple requests-headers per tcp connection, terminate
		// previous with a single newline.
		if (buf_tell(&outbuf) > 0)
			buf_putf(&outbuf, "\n");
		
		if (type[0] == 'G' && auth) {
			req = http_req_dirname(req);
		}

		if (Opt_color) {
			if (gquery) {
				*(gquery - 1) = '\0';
				buf_putf(&outbuf, CB"%s"CDC" %s"CN"?%s", type, uri_prot, gquery);
				*(gquery -1) = '?';
			} else {
				if ((p = strchr(uri_prot, ' ')) != NULL) {
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
		if (is_hot) 
			dc_meta.is_hot = 1;
		
		int is_add_uri_dc = 0;
		if (!(cookie && (!(is_pquery_hot || is_gquery_hot)))) {
			// If we have a COOKIE but nothing else that's "hot" in this request
			// then do not add the URL to the DUP-check. Only add the cookie to prevent
			// the same cookie showing again and again.
			is_add_uri_dc = 1; // we got something else that's hot (and also a cookie)
		} 
		// DUP check up to '?'
		// Anti-Sub-domain-Fuzzing: Ignore requests to same host with different 'req'
		// On "-vv" add URI to DUP-check (and thus log different URIs)
		if ((is_http_ok) && is_add_uri_dc && (is_hot || (Opt_verbose >= 2)) ) {
			// HERE: Do NOT show duplicates.
			if (gquery)
				dc_update(&dc_meta, req, gquery - 1 - req); // Only dup-check up to "?"
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
			location = strchr(location, '?');
			if (location)
				location++;
		}
		if (agent)
			buf_putf(&outbuf, "\n%s", agent);
		buf_hot_header(&outbuf, key);
		buf_hot_header(&outbuf, bearer);

		if (cookie) {
			if (Opt_color)
				buf_putf(&outbuf, "\n"CDR"Cookie"CN": %s", cookie);
			else
				buf_putf(&outbuf, "\nCookie: %s", cookie);

			// Decoded output:
			if (Opt_color)
				buf_put(&outbuf, CF, sizeof CF - 1);
			// De-facto standard is to URL-encode cookies.
			buf_hot_form(&outbuf, cookie, ';', BUF_FORM_FL_NO_COLOR | BUF_FORM_FL_DECODE_PLUS | BUF_FORM_FL_DO_DECODE | BUF_FORM_FL_SKIP_SINGLE);
			if (Opt_color)
				buf_put(&outbuf, CN, sizeof CN - 1);

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

		if (location) {
			// HERE: Location contains a GET query-string (after '?')
			if (is_location_hot || Opt_verbose) {
				buf_hot_form(&outbuf, location, '&', BUF_FORM_FL_SKIP_SINGLE | BUF_FORM_FL_DO_DECODE | (is_location_hot?BUF_FORM_FL_IS_HOT:0));
			}
		}
		if (is_gquery_hot || Opt_verbose) {
			if (gquery) {
					char *str = strchr(gquery, ' ');
					if (*str)
						*str = '\0';
			}
			if (is_form)
				buf_hot_form(&outbuf, gquery, '&', BUF_FORM_FL_DECODE_PLUS | BUF_FORM_FL_SKIP_SINGLE | BUF_FORM_FL_DO_DECODE | (is_gquery_hot?BUF_FORM_FL_IS_HOT:0));
			else
				buf_hot_form(&outbuf, gquery, '&', BUF_FORM_FL_DECODE_PLUS | BUF_FORM_FL_SKIP_SINGLE | (is_gquery_hot?BUF_FORM_FL_IS_HOT:0)); // type NOT x-www-form-urlencoded but still contains a query string.
		}
		while (is_pquery_hot || Opt_verbose) {
			if ((is_form) && (pquery && isprint(*pquery))) {
				buf_hot_form(&outbuf, gquery, '&', BUF_FORM_FL_DECODE_PLUS | BUF_FORM_FL_DO_DECODE | (is_pquery_hot?BUF_FORM_FL_IS_HOT:0));
				break;
			}
			buf_hot(&outbuf, pquery, cont_len, is_pquery_hot);
			break;
		}
	} //while ((i = buf_index(&inbuf, "\r\n\r\n", 4)) >= 0) 
	buf_end(&outbuf);

	// HTTP response was not 2xx. Only log if Cookie/Auth was found.
	if (dc_meta.is_hot || (Opt_verbose && is_http_ok))
		return buf_len(&outbuf);

	return 0;
}
