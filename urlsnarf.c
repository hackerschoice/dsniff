/*
 * urlsnarf.c
 *
 * Sniff the network for HTTP request URLs, output in CLF format.
 *
 * Copyright (c) 1999 Dug Song <dugsong@monkey.org>
 *
 * $Id: urlsnarf.c,v 1.35 2001/03/15 09:26:13 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <time.h>
#include <err.h>
#include <libnet.h>
#include <nids.h>
#include <pcap.h>

#include "pcaputil.h"
#include "buf.h"
#include "base64.h"
#include "version.h"

#define DEFAULT_PCAP_FILTER "tcp port 80 or port 8080 or port 3128"

u_short		Opt_dns = 1;
int		Opt_invert = 0;
regex_t	       *pregex = NULL;
time_t          tt = 0;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: urlsnarf [-n] [-i interface | -p pcapfile] [[-v] pattern [expression]]\n");
	exit(1);
}

static int
regex_match(char *string)
{
	return (pregex == NULL ||
		((regexec(pregex, string, 0, NULL, 0) == 0) ^ Opt_invert));
}

static char *
timestamp(void)
{
	static char tstr[32], sign;
	struct tm *t, gmt;
	int days, hours, tz, len;
	
	if (!nids_params.filename) {
		tt = time(NULL);
	}
	
	gmt = *gmtime(&tt);
	t = localtime(&tt);
	
	days = t->tm_yday - gmt.tm_yday;
	hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24) +
		 t->tm_hour - gmt.tm_hour);
	tz = hours * 60 + t->tm_min - gmt.tm_min;
	
	len = strftime(tstr, sizeof(tstr), "%d/%b/%Y:%X", t);
	if (len < 0 || len > sizeof(tstr) - 5)
		return (NULL);
	
	if (tz < 0) {
		sign = '-';
		tz = -tz;
	}
	else sign = '+';
	
	snprintf(tstr + len, sizeof(tstr) - len, " %c%.2d%.2d",
		 sign, tz / 60, tz % 60);
	
	return (tstr);
}

static char *
escape_log_entry(char *string)
{
	char *out;
	unsigned char *c, *o;
	size_t len;

	if (!string)
		return NULL;

	/* Determine needed length */
	for (c = string, len = 0; *c; c++) {
		if ((*c < 32) || (*c >= 128))
			len += 4;
		else if ((*c == '"') || (*c =='\\'))
			len += 2;
		else
			len++;
	}
	out = malloc(len+1);
	if (!out)
		return NULL;
	for (c = string, o = out; *c; c++, o++) {
		if ((*c < 32) || (*c >= 128)) {
			snprintf(o, 5, "\\x%02x", *c);
			o += 3;
		} else if ((*c == '"') || ((*c =='\\'))) {
			*(o++) = '\\';
			*o = *c;
		} else {
			*o = *c;
		}
	}
	out[len]='\0';
	return out;
}

static int
process_http_request(struct tuple4 *addr, u_char *data, int len)
{
	struct buf *msg, buf;
	char *p, *req, *uri, *user, *vhost, *referer, *agent;
	int i;

	buf_init(&buf, data, len);
	
	while ((i = buf_index(&buf, "\r\n\r\n", 4)) >= 0) {
		msg = buf_tok(&buf, NULL, i);
		msg->base[msg->end] = '\0';
		buf_skip(&buf, 4);
		
		if (!regex_match(buf_ptr(msg)))
			continue;
		
		if ((req = strtok(buf_ptr(msg), "\r\n")) == NULL)
			continue;
		
		if (strncmp(req, "GET ", 4) != 0 &&
		    strncmp(req, "POST ", 5) != 0 &&
		    strncmp(req, "CONNECT ", 8) != 0)
			continue;
		
		if ((uri = strchr(req, ' ')) == NULL)
			continue;

		*uri++ = '\0';
		if (strncmp(uri, "http://", 7) == 0) {
			for (uri += 7; *uri != '/'; uri++)
				;
		}
		user = vhost = referer = agent = NULL;
		
		while ((p = strtok(NULL, "\r\n")) != NULL) {
			if (strncasecmp(p, "Authorization: Basic ", 21) == 0) {
				p += 21;
				i = base64_pton(p, p, strlen(p));
				p[i] = '\0';
				user = p;
				if ((p = strchr(p, ':')) != NULL)
					*p = '\0';
			}
			else if (strncasecmp(p, "Host: ", 6) == 0) {
				vhost = p + 6;
			}
			else if (strncasecmp(p, "Referer: ", 9) == 0) {
				referer = p + 9;
			}
			else if (strncasecmp(p, "User-Agent: ", 12) == 0) {
				agent = p + 12;
			}
			else if (strncasecmp(p, "Content-length: ", 16) == 0) {
				i = atoi(p + 16);
				buf_tok(NULL, NULL, i);
			}
		}
		user = escape_log_entry(user);
		vhost = escape_log_entry(vhost);
		uri = escape_log_entry(uri);
		referer = escape_log_entry(referer);
		agent = escape_log_entry(agent);

		printf("%s - %s [%s] \"%s http://%s%s\" - - \"%s\" \"%s\"\n",
		       libnet_addr2name4(addr->saddr, Opt_dns),
		       (user?user:"-"),
		       timestamp(), req, 
		       (vhost?vhost:libnet_addr2name4(addr->daddr, Opt_dns)), 
		       uri,
		       (referer?referer:"-"),
		       (agent?agent:"-"));

		free(user);
		free(vhost);
		free(uri);
		free(referer);
		free(agent);
	}
	fflush(stdout);
	
	return (len - buf_len(&buf));
}

static void
sniff_http_client(struct tcp_stream *ts, void **yoda)
{
	int i;
	
	switch (ts->nids_state) {

	case NIDS_JUST_EST:
		ts->server.collect = 1;
		
	case NIDS_DATA:
		if (ts->server.count_new != 0) {
			i = process_http_request(&ts->addr, ts->server.data,
						 ts->server.count -
						 ts->server.offset);
			nids_discard(ts, i);
		}
		break;
		
	default:
		if (ts->server.count != 0) {
			process_http_request(&ts->addr, ts->server.data,
					     ts->server.count -
					     ts->server.offset);
		}
		break;
	}
}

static void
null_syslog(int type, int errnum, struct ip *iph, void *data)
{
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;
	struct nids_chksum_ctl chksum_ctl;
	
	while ((c = getopt(argc, argv, "i:p:nvh?V")) != -1) {
		switch (c) {
		case 'i':
			nids_params.device = optarg;
			break;
		case 'p':
			nids_params.filename = optarg;
			break;
		case 'n':
			Opt_dns = 0;
			break;
		case 'v':
			Opt_invert = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0 && strlen(argv[0])) {
		if ((pregex = (regex_t *) malloc(sizeof(*pregex))) == NULL)
			err(1, "malloc");
		if (regcomp(pregex, argv[0], REG_EXTENDED|REG_NOSUB) != 0)
			errx(1, "invalid regular expression");
	}
	if (argc > 1) {
		nids_params.pcap_filter = copy_argv(argv + 1);
	}
	else nids_params.pcap_filter = DEFAULT_PCAP_FILTER;
	
	nids_params.scan_num_hosts = 0;
	nids_params.syslog = null_syslog;
	
	if (!nids_init())
		errx(1, "%s", nids_errbuf);
	
	nids_register_tcp(sniff_http_client);

        if (nids_params.pcap_filter != NULL) {
                if (nids_params.filename == NULL) {
                        warnx("listening on %s [%s]", nids_params.device,
                              nids_params.pcap_filter);
                }
                else {
                        warnx("using %s [%s]", nids_params.filename,
                              nids_params.pcap_filter);
                }
        }
        else {
                if (nids_params.filename == NULL) {
                    warnx("listening on %s", nids_params.device);
                }
                else {
                    warnx("using %s", nids_params.filename);
                }
        }

        chksum_ctl.netaddr = 0;
        chksum_ctl.mask = 0;
        chksum_ctl.action = NIDS_DONT_CHKSUM;

        nids_register_chksum_ctl(&chksum_ctl, 1);

	pcap_t *p;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	if (nids_params.filename == NULL) {
		/* adapted from libnids.c:open_live() */
		if (strcmp(nids_params.device, "all") == 0)
			nids_params.device = "any";
		p = pcap_open_live(nids_params.device, 16384, 
				   (nids_params.promisc != 0),
				   0, pcap_errbuf);
		if (!p) {
			fprintf(stderr, "pcap_open_live(): %s\n",
				pcap_errbuf);
			exit(1);
		}
	}
	else {
		p = pcap_open_offline(nids_params.filename, 
				      pcap_errbuf);
		if (!p) {
			fprintf(stderr, "pcap_open_offline(%s): %s\n",
				nids_params.filename, pcap_errbuf);
		}
	}

	struct pcap_pkthdr *h;
	u_char *d;
	int rc;
	while ((rc = pcap_next_ex(p, &h, &d)) == 1) {
		tt = h->ts.tv_sec;
		nids_pcap_handler(NULL, h, d);
	}
	switch (rc) {
	case(-2): /* end of pcap file */
	case(0):  /* timeout on live capture */
		break;
	case(-1):
	default:
		fprintf(stderr, "rc = %i\n", rc);
		pcap_perror(p, "pcap_read_ex()");
		exit(1);
		break;
	}
	
	exit(0);
}
