// grep -v ^# dsniff.magic | while read -r x; do echo '"'"${x//\\/\\\\}"'", \'; done >>dsniff_magic.h

static char *mgx[] = {\
"0	string		BEGIN\\ 		cvs", \
"", \
"0	string		SYST		ftp", \
"0	string		USER\\ ftp	ftp", \
"0	string		USER\\ anonymous	ftp", \
"", \
"0	string		HELO\\ 		smtp", \
"0	string		EHLO\\ 		smtp", \
"", \
"0	string		GET\\ /		http", \
"0	string		POST\\ /		http", \
"0	string		CONNECT\\ 	http", \
"", \
"1	string		\\ ID\\ 	imap", \
"2	string		\\ ID\\ 	imap", \
"3	string		\\ ID\\ 	imap", \
"4	string		\\ ID\\ 	imap", \
"5	string		\\ ID\\ 	imap", \
"", \
"1	string		\\ LOGIN\\ 	imap", \
"2	string		\\ LOGIN\\ 	imap", \
"3	string		\\ LOGIN\\ 	imap", \
"4	string		\\ LOGIN\\ 	imap", \
"5	string		\\ LOGIN\\ 	imap", \
"", \
"1	string		\\ AUTHENTICATE\\ PLAIN\\ 	imap", \
"2	string		\\ AUTHENTICATE\\ PLAIN\\ 	imap", \
"3	string		\\ AUTHENTICATE\\ PLAIN\\ 	imap", \
"4	string		\\ AUTHENTICATE\\ PLAIN\\ 	imap", \
"5	string		\\ AUTHENTICATE\\ PLAIN\\ 	imap", \
"", \
"0	string		NICK\\ 		irc", \
"", \
"0	string		USER\\ 		pop3", \
"0	string		AUTH\\ 		pop3", \
"", \
"12	string		MIT-MAGIC	x11", \
"", \
"0	string		LIST		nntp", \
"0	string		GROUP		nntp", \
"0	string		NEW		nntp", \
"0	string		ARTICLE		nntp", \
"", \
"0	belong		0x7f7f4943", \
">4	beshort		0x4100		citrix", \
"", \
"", \
"0	beshort		0x1603", \
">2	byte		0x01", \
">>5	byte		0x01", \
">>>9	byte		0x03		https", \
"", \
"8	belong		0x0135012c", \
">12	belong		0x0c010800", \
">>16	belong		0x7fff7f08", \
">>>20	belong		0x00000001	oracle", \
"", \
"0	belong		0x0", \
">4	byte		0x8d		pcanywhere", \
">5	byte		0x6		pcanywhere", \
"", \
"132	belong		0x0301060a", \
">242	belong		0		tds", \
"32	belong		0xe0031000", \
">36	belong		0x2c010000	tds", \
"", \
"12	belong		100000", \
">4	belong		0", \
">>8	belong		2		portmap", \
"12	belong		100005", \
">4	belong		0", \
">>8	belong		2		mountd", \
"12	belong		100009", \
">4	belong		0", \
">>8	belong		2		yppasswd", \
"", \
"16	belong		100000", \
">8	belong		0", \
">>12	belong		2		portmap", \
"16	belong		100005", \
">8	belong		0", \
">>12	belong		2		mountd", \
"16	belong		100009", \
">8	belong		0", \
">>12	belong		2		yppasswd", \
"", \
"0	belong		296", \
">4	belong		0x20000		postgresql", \
"", \
"0	belong		0x81000048", \
">33	string		CACA	 	smb", \
"", \
"0	beshort		>0xfff9", \
">2	byte		<40", \
">>3	beshort		>0xfff9", \
">>>5	byte		<40		telnet", \
"", \
"0	string		SSH-		ssh", \
"", \
"", \
"0	byte		0x38", \
">8	belong		0x00002455	mmxp", \
"", \
"0	byte		5", \
">6	leshort		260", \
">>32	byte		0		sniffer", \
">6	leshort		261", \
">>32	lelong		-1		sniffer", \
">1	belong		0", \
">>5	byte		0		icq", \
">(1.b+1)	byte	1		socks", \
"", \
"0	byte&0x1f	16", \
">2	byte&0x1f	2", \
">>5	byte		0x60		ldap", \
">4	byte&0x1f	2", \
">>5	beshort&0xfffc	0x0100", \
">>>7	byte&0x1f	4		snmp", \
};
