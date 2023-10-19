

//grep -v ^# dsniff.services | while read -r x; do s="${x##*$'\t'}"; echo -e '{"'"${x%%$'\t'*}"'"'", ${s%%\/*}, DSNIFF_SERVICE_${s##*/}},";  done | column -t  >>dsniff_services.h

struct _ds_service {
    char *name;
    int port;
    char *proto;
};

#define DSNIFF_SERVICE_tcp      "tcp"
#define DSNIFF_SERVICE_ip       "ip"
#define DSNIFF_SERVICE_udp      "udp"
#define DSNIFF_SERVICE_rpc      "rpc"
static struct _ds_service dsx[] = {
{"ftp",         21,      DSNIFF_SERVICE_tcp},
{"ssh",         22,      DSNIFF_SERVICE_tcp},
{"telnet",      23,      DSNIFF_SERVICE_tcp},
{"smtp",        25,      DSNIFF_SERVICE_tcp},
{"pptp",        47,      DSNIFF_SERVICE_ip},
{"http",        80,      DSNIFF_SERVICE_tcp},
{"ospf",        89,      DSNIFF_SERVICE_ip},
{"http",        98,      DSNIFF_SERVICE_tcp},
{"poppass",     106,     DSNIFF_SERVICE_tcp},
{"pop2",        109,     DSNIFF_SERVICE_tcp},
{"pop3",        110,     DSNIFF_SERVICE_tcp},
{"portmap",     111,     DSNIFF_SERVICE_tcp},
{"portmap",     -111,    DSNIFF_SERVICE_tcp},
{"portmap",     111,     DSNIFF_SERVICE_udp},
{"portmap",     -111,    DSNIFF_SERVICE_udp},
{"vrrp",        112,     DSNIFF_SERVICE_ip},
{"nntp",        119,     DSNIFF_SERVICE_tcp},
{"smb",         139,     DSNIFF_SERVICE_tcp},
{"imap",        143,     DSNIFF_SERVICE_tcp},
{"snmp",        161,     DSNIFF_SERVICE_udp},
{"imap",        220,     DSNIFF_SERVICE_tcp},
{"telnet",      261,     DSNIFF_SERVICE_tcp},
{"ldap",        389,     DSNIFF_SERVICE_tcp},
{"mmxp",        417,     DSNIFF_SERVICE_tcp},
{"mmxp",        417,     DSNIFF_SERVICE_udp},
{"https",       443,     DSNIFF_SERVICE_tcp},
{"rlogin",      512,     DSNIFF_SERVICE_tcp},
{"rlogin",      513,     DSNIFF_SERVICE_tcp},
{"rlogin",      514,     DSNIFF_SERVICE_tcp},
{"rip",         520,     DSNIFF_SERVICE_udp},
{"smtp",        587,     DSNIFF_SERVICE_tcp},
{"socks",       1080,    DSNIFF_SERVICE_tcp},
{"tds",         1433,    DSNIFF_SERVICE_tcp},
{"tds",         1433,    DSNIFF_SERVICE_udp},
{"citrix",      1494,    DSNIFF_SERVICE_tcp},
{"oracle",      1521,    DSNIFF_SERVICE_tcp},
{"oracle",      1526,    DSNIFF_SERVICE_tcp},
{"sniffer",     2001,    DSNIFF_SERVICE_udp},
{"cvs",         2401,    DSNIFF_SERVICE_tcp},
{"mmxp",        2417,    DSNIFF_SERVICE_tcp},
{"mmxp",        2417,    DSNIFF_SERVICE_udp},
{"tds",         2638,    DSNIFF_SERVICE_tcp},
{"http",        3128,    DSNIFF_SERVICE_tcp},
{"icq",         4000,    DSNIFF_SERVICE_udp},
//{"napster",     4444,    DSNIFF_SERVICE_tcp},
// {"aim",         5190,    DSNIFF_SERVICE_tcp},
{"postgresql",  5432,    DSNIFF_SERVICE_tcp},
// {"napster",     5555,    DSNIFF_SERVICE_tcp},
{"pcanywhere",  5631,    DSNIFF_SERVICE_tcp},
{"x11",         6000,    DSNIFF_SERVICE_tcp},
{"x11",         6001,    DSNIFF_SERVICE_tcp},
{"x11",         6002,    DSNIFF_SERVICE_tcp},
{"x11",         6003,    DSNIFF_SERVICE_tcp},
{"x11",         6004,    DSNIFF_SERVICE_tcp},
{"x11",         6005,    DSNIFF_SERVICE_tcp},
// {"napster",     6666,    DSNIFF_SERVICE_tcp},
{"irc",         6667,    DSNIFF_SERVICE_tcp},
{"irc",         6668,    DSNIFF_SERVICE_tcp},
{"irc",         6669,    DSNIFF_SERVICE_tcp},
{"tds",         7599,    DSNIFF_SERVICE_tcp},
// {"napster",     7777,    DSNIFF_SERVICE_tcp},
{"http",        8080,    DSNIFF_SERVICE_tcp},
// {"napster",     8888,    DSNIFF_SERVICE_tcp},
// {"aim",         9898,    DSNIFF_SERVICE_tcp},
{"pcanywhere",  65301,   DSNIFF_SERVICE_tcp},
{"mountd",      100005,  DSNIFF_SERVICE_rpc},
{"ypserv",      100004,  DSNIFF_SERVICE_rpc},
{"yppasswd",    100009,  DSNIFF_SERVICE_rpc}
};