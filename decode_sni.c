#include "config.h"

#include <sys/types.h>
#include <arpa/inet.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strlcpy.h>
#include <ctype.h>

#include "options.h"
#include "decode.h"

extern struct _dc_meta dc_meta;

struct tls_hdr {
	uint8_t proto;
	uint16_t vers;
	uint16_t len;
} __attribute__((packed));

struct tls_ch {
	uint8_t type;
	uint8_t len[3];
	uint16_t version;  /// 03 03 for TLS 1.2 and TLS 1.3
	uint8_t random[32];
	uint8_t sid_len;
} __attribute__((packed));

struct tls_ex {
	uint16_t type;
	uint16_t len;
} __attribute__((packed));

int
decode_sni(u_char *buf, int len, u_char *obuf, int olen) {
	u_char *end = buf + len;
	u_char *ptr = buf;
	struct tls_hdr *t = (struct tls_hdr *)buf;
	struct tls_ch *ch;
	uint16_t hls;
	uint16_t type;

	if (!Opt_verbose)
		return 0;

	// FILE *fp = fopen("dump.hex", "w");
	// fwrite(buf, len, 1, fp);
	// fclose(fp);

	if (len <= sizeof (struct tls_hdr) + sizeof (struct tls_ch) /* + sid_len */ + sizeof (struct tls_ex))
		return 0;

	memcpy(&hls, &t->len, 2);
	hls = ntohs(hls);
	memset(&t->len, 0, 2);

	if (memcmp(buf, "\x16\x03\x01\x00\x00\x01", 6) != 0)
		return 0;

	// Skip TLS header
	ptr += sizeof *t;
	if (end - ptr < sizeof *ch)
		return 0;
	ch = (struct tls_ch *)ptr;
	// Skip fixed ClientHelo
	if (ptr[5] != 0x03) // ch->verison[1] 
		return 0;
	ptr += sizeof *ch;
	ptr += ch->sid_len;  // Skip Session-ID
	if (ptr >= end)
		return 0;
	
	memcpy(&hls, ptr, 2);
	hls = ntohs(hls);
	ptr += hls + 2; // Skip length + Cipher Suites
	if (ptr >= end)
		return 0;
	
	ptr += (ptr[0] + 1); // Skip length + Compression Methods

	if (ptr + 2 >= end)
		return 0;
	memcpy(&hls, ptr, 2);
	hls = ntohs(hls);
	ptr += 2;

	// Ignore garbage after extensions (should not be any)
	if (ptr + hls < end)
		end = ptr + hls;
	// Iterate through all TLS extensions until we find SNI.
	while (1) {
		fprintf(stderr, "MARK %d\n", __LINE__);

		if (ptr + sizeof (struct tls_ex) + 2 /* SNI List Length */ + 1 /* SNI Type */ >= end)
			goto err;
		fprintf(stderr, "MARK %d\n", __LINE__);

		memcpy(&type, ptr, 2);
		type = htons(type);
		fprintf(stderr, "type=%x\n", type);
		if (type != 0) {
			memcpy(&hls, ptr + 2, 2);
			hls = htons(hls);
		fprintf(stderr, "len=%d\n", len);
			ptr += sizeof (struct tls_ex) + hls;
			continue;
		}
		// SNI
		ptr += sizeof (struct tls_ex);
		fprintf(stderr, "MARK %d\n", __LINE__);

		ptr += 2; // List Length.
		if (ptr >= end)
			goto err;
		if (*ptr != 0x00)
			goto err;
		ptr += 1; // SN Type.
		if (ptr + 2 >= end)
			goto err;
		memcpy(&hls, ptr, 2);
		hls = htons(hls);
		ptr += 2; // SN Length
		fprintf(stderr, "MARK %d\n", __LINE__);

		if (ptr + hls + 1 >= end) // SNI is never the last. Make sure there is \0 for the \0.
			goto err;
		snprintf(obuf, olen, "SNI: %s", ascii_string(ptr, hls + 1));
		fprintf(stderr, "MARK %d '%s'\n", __LINE__, ascii_string(ptr, hls + 1));

		break;
	}
		fprintf(stderr, "MARK %d\n", __LINE__);

	return (strlen(obuf));
err:
	return 0;
}

