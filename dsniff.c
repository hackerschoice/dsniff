/*
 * dsniff.c
 *
 * Password sniffer, because DrHoney wanted one.
 *
 * This is intended for demonstration purposes and educational use only.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: dsniff.c,v 1.69 2001/03/15 08:33:03 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>
#include <libnet.h>
#include <nids.h>
#include <pcap.h>

#include "options.h"
#include "pathnames.h"
#include "pcaputil.h"
#include "trigger.h"
#include "record.h"
#include "env2argv.h"

#define MAX_LINES	6
#define MIN_SNAPLEN	1024

int	Opt_client = 0;
int	Opt_debug = 0;
u_short	Opt_dns = 0;
int	Opt_magic = 0;
int	Opt_read = 0;
int	Opt_write = 0;
int	Opt_snaplen = MIN_SNAPLEN;
int	Opt_lines = MAX_LINES;
int Opt_verbose = 0;
int Opt_show_dups = 0;
int Opt_color = 0;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
"Usage: dsniff [-cdamNPCv] [-i interface | -p pcapfile] [-s snaplen]\n"
"              [-f services] [-t trigger[,...]] [-r|-w savefile]\n"
"              [expression]\n"
" -c         Half-duplex TCP stream assembly\n"
" -a         Show duplicates\n"
" -v         Verbose. Show banners\n"
" -d         Enable debugging mode\n"
" -m         Enable protocol detection and DPI. Use twice (-m -m) to also DPI known ports\n"
" -C         Force color output even if not a TTY\n"
" -N         Resolve IP addresses to hostname\n"
" -P         Enable promisc mode\n"
" -i <link>  Specify the interface to listen on\n"
" -p <file>  Read from pcap file\n"
" -s <len>   Analyze at most the first snaplen of each TCP connection [default: %d]\n"
" -w <db>    Write sniffed sessions to db rather then printing them out\n"
" -r <db>    Read sniffed sessions from a db created with the -w option\n"
"\n" 
" Example:\n"
"   dsniff -i eth0 -C -m -m >log.txt\n", MIN_SNAPLEN);
	exit(1);
}

static void
sig_hup(int sig)
{
	trigger_dump();
}

static void
sig_die(int sig)
{
	record_close();
	exit(0);
}

static void
null_syslog(int type, int errnum, struct ip *iph, void *data)
{
}


static int get_all_ifaces(struct ifreq **, int *);
static unsigned int get_addr_from_ifreq(struct ifreq *);

int all_local_ipaddrs_chksum_disable()
{
	struct ifreq *ifaces;
	int ifaces_count;
	int i, ind = 0;
	struct nids_chksum_ctl *ctlp;
	unsigned int tmp;

	if (!get_all_ifaces(&ifaces, &ifaces_count))
		return -1;
	ctlp =
	    (struct nids_chksum_ctl *) malloc(ifaces_count *
					      sizeof(struct
						     nids_chksum_ctl));
	if (!ctlp)
		return -1;
	for (i = 0; i < ifaces_count; i++) {
		tmp = get_addr_from_ifreq(ifaces + i);
		if (tmp) {
			ctlp[ind].netaddr = tmp;
			ctlp[ind].mask = inet_addr("255.255.255.255");
			ctlp[ind].action = NIDS_DONT_CHKSUM;
			ind++;
		}
	}
	free(ifaces);
	nids_register_chksum_ctl(ctlp, ind);
}

/* helper functions for Example 2 */
unsigned int get_addr_from_ifreq(struct ifreq *iface)
{
	if (iface->ifr_addr.sa_family == AF_INET)
		return ((struct sockaddr_in *) &(iface->ifr_addr))->
		    sin_addr.s_addr;
	return 0;
}

static int get_all_ifaces(struct ifreq **ifaces, int *count)
{
	int ifaces_size = 8 * sizeof(struct ifreq);
	struct ifconf param;
	int sock;
	unsigned int i;

	*ifaces = malloc(ifaces_size);
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock <= 0)
		return 0;
	for (;;) {
		param.ifc_len = ifaces_size;
		param.ifc_req = *ifaces;
		if (ioctl(sock, SIOCGIFCONF, &param))
			goto err;
		if (param.ifc_len < ifaces_size)
			break;
		free(*ifaces);
		ifaces_size *= 2;
		ifaces = malloc(ifaces_size);
	}
	*count = param.ifc_len / sizeof(struct ifreq);
	close(sock);
	return 1;
      err:
	close(sock);
	return 0;
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	char *services, *savefile, *triggers, *magics;
	int c;

	env2argv(&argc, &argv);
	services = savefile = triggers = magics = NULL;
	
	if (isatty(STDOUT_FILENO))
		Opt_color = 1;

	nids_params.promisc = 0;

	while ((c = getopt(argc, argv, "PCvcdaM:f:i:mNnp:r:s:t:w:h?V")) != -1) {
		switch (c) {
		case 'P':
			nids_params.promisc = 1;
			break;
		case 'C':
			Opt_color = 2; // FORCED
			break;
		case 'v':
			Opt_verbose = 1;
			break;
		case 'c':
			Opt_client = 1;
			break;
		case 'a':
			Opt_show_dups++;
			break;
		case 'd':
			Opt_debug++;
			break;
		case 'f':
			services = optarg;
			break;
		case 'M':
			magics = optarg;
			break;
		case 'i':
			nids_params.device = optarg;
			break;
		case 'm':
			Opt_magic++;
			break;
		case 'N':
			Opt_dns = 1;
			break;
		case 'n':
			// compat mode
			Opt_dns = 0;
			break;
		case 'p':
			nids_params.filename = optarg;
			break;
		case 'r':
			Opt_read = 1;
			savefile = optarg;
			break;
		case 's':
			if ((Opt_snaplen = atoi(optarg)) == 0)
				usage();
			break;
		case 't':
			triggers = optarg;
			trigger_init_list(triggers);
			break;
		case 'w':
			Opt_write = 1;
			savefile = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (Opt_read && Opt_write)
		usage();
	if (Opt_write && (Opt_color < 2))
		Opt_color = 0; // Disable color for to DB.
	
	if (!record_init(savefile))
		err(1, "record_init");
	
	signal(SIGHUP, sig_hup);
	signal(SIGINT, sig_die);
	signal(SIGTERM, sig_die);
	
	if (Opt_read) {
		record_dump();
		record_close();
		exit(0);
	}

	if (argc != 0)
		nids_params.pcap_filter = copy_argv(argv);
	nids_params.scan_num_hosts = 0;
	nids_params.syslog = null_syslog;
	nids_params.n_tcp_streams = 8 * 1024;
	nids_params.tcp_workarounds = 1;
	
	if (!nids_init()) {
		record_close();
		errx(1, "nids_init: %s", nids_errbuf);
	}

	// Only load if manual triggers are not used.
	if (triggers == NULL) {
		if (Opt_magic)
			trigger_init_magic(magics);
		// if -m -m then only trigger on MAGIC (and ignoring dsniff.services completely)
		// -m _OR_ -f <foobar>
		if ((Opt_magic <= 1) || (services != NULL))
			trigger_init_services(services);
	}
	
	nids_register_ip(trigger_ip);
	nids_register_ip(trigger_udp);
		
	if (Opt_client) {
		nids_register_ip(trigger_tcp_raw);
		signal(SIGALRM, trigger_tcp_raw_timeout);
		alarm(TRIGGER_TCP_RAW_TIMEOUT);
	}
	else nids_register_tcp(trigger_tcp);
	
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

	// all_local_ipaddrs_chksum_disable();
	// In Docker containers the chksum is often wrong even if not send from any
	// of the local NICs (local to the PHY but not visible by the container)....
	struct nids_chksum_ctl chksum_conf = { 0, 0, NIDS_DONT_CHKSUM };
	nids_register_chksum_ctl(&chksum_conf, 1);

	nids_run();
	
	/* NOTREACHED */
	
	exit(0);
}
