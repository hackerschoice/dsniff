#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "env2argv.h"

#define ARGS_NAME    "ENV_ARGS"

// Add list of argv's from environment to argv[].
// Result: argv[0] + ENV_ARGS[@] + argv[1..n]
void
env2argv(int *argcptr, char **argvptr[]) {
	char *str_orig = getenv(ARGS_NAME);
	char *str = NULL;
	char *next;
	char **newargv = NULL;
	int newargc = 0;

	if ((str_orig == NULL) || (*str_orig == '\0'))
		return;

	str = strdup(str_orig);
	next = str;

	newargv = malloc(1 * sizeof *argvptr);
	memcpy(&newargv[0], argvptr[0], 1 * sizeof *argvptr);
	newargc = 1; 

	while (next != NULL) {
		while (*str == ' ')
			str++;

		next = strchr(str, ' ');
		if (next != NULL) {
			*next = 0;
			next++;
		}
		// catch if last character is ' '
		if (strlen(str) > 0) {
			/* *next == '\0'; str points to argument (0-terminated) */
			newargc++;
			// DEBUGF("%d. arg = '%s'\n", newargc, str);
			newargv = realloc(newargv, newargc * sizeof newargv);
			newargv[newargc - 1] = str;
		}

		str = next;
		if (str == NULL)
			break;
	}

	// Copy original argv[1..n]
	newargv = realloc(newargv, (newargc + *argcptr) * sizeof newargv);
	memcpy(newargv + newargc, *argvptr + 1, (*argcptr - 1) * sizeof *argvptr);

	newargc += (*argcptr - 1);
	newargv[newargc] = NULL;

	*argcptr = newargc;
	*argvptr = newargv;
}