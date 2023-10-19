#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <strlcpy.h>
#include <ctype.h>

#include "options.h"
#include "decode.h"

extern struct _dc_meta dc_meta;

int
decode_ssh(u_char *buf, int len, u_char *obuf, int olen) {
	u_char *ptr = "";

	if (!Opt_verbose)
		return 0;

	if (strncmp(buf, "SSH-", 4) != 0)
		return 0;

	if (dc_meta.rbuf != NULL)
		ptr = ascii_string(dc_meta.rbuf, dc_meta.rlen);

	snprintf(obuf, olen, "%s >>> %s", ascii_string(buf, len), ptr);
	
	return (strlen(obuf));
}

