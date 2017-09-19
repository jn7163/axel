#include "config.h"

#ifdef CRYPTO_OPENSSL

#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

#include <openssl/asn1.h>

#define GENTIME_LENGTH 15
#define UTCTIME_LENGTH 13

size_t
strlcpy(char *dst, const char *src, size_t dsize)
{
	strncpy(dst, src, dsize - 1);
	dst[dsize - 1] = '\0';

	return strlen(src);
}

#define MUL_NO_OVERFLOW ((size_t)1 << (sizeof(size_t) * 4))

void *
reallocarray(void *optr, size_t nmemb, size_t size)
{
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(optr, size * nmemb);
}

void
freezero(void *ptr, size_t size)
{
	free(ptr);
}

int
ASN1_time_tm_clamp_notafter(struct tm *tm)
{
	return 1;
}

/*
 * Parse an RFC 5280 format ASN.1 time string.
 *
 * mode must be:
 * 0 if we expect to parse a time as specified in RFC 5280 for an X509 object.
 * V_ASN1_UTCTIME if we wish to parse an RFC5280 format UTC time.
 * V_ASN1_GENERALIZEDTIME if we wish to parse an RFC5280 format Generalized time.
 *
 * Returns:
 * -1 if the string was invalid.
 * V_ASN1_UTCTIME if the string validated as a UTC time string.
 * V_ASN1_GENERALIZEDTIME if the string validated as a Generalized time string.
 *
 * Fills in *tm with the corresponding time if tm is non NULL.
 */
#define	ATOI2(ar)	((ar) += 2, ((ar)[-2] - '0') * 10 + ((ar)[-1] - '0'))
int
ASN1_time_parse(const char *bytes, size_t len, struct tm *tm, int mode)
{
	size_t i;
	int type = 0;
	struct tm ltm;
	struct tm *lt;
	const char *p;

	if (bytes == NULL)
		return (-1);

	/* Constrain to valid lengths. */
	if (len != UTCTIME_LENGTH && len != GENTIME_LENGTH)
		return (-1);

	lt = tm;
	if (lt == NULL) {
		memset(&ltm, 0, sizeof(ltm));
		lt = &ltm;
	}

	/* Timezone is required and must be GMT (Zulu). */
	if (bytes[len - 1] != 'Z')
		return (-1);

	/* Make sure everything else is digits. */
	for (i = 0; i < len - 1; i++) {
		if (isdigit((unsigned char)bytes[i]))
			continue;
		return (-1);
	}

	/*
	 * Validate and convert the time
	 */
	p = bytes;
	switch (len) {
	case GENTIME_LENGTH:
		if (mode == V_ASN1_UTCTIME)
			return (-1);
		lt->tm_year = (ATOI2(p) * 100) - 1900;	/* cc */
		type = V_ASN1_GENERALIZEDTIME;
		/* FALLTHROUGH */
	case UTCTIME_LENGTH:
		if (type == 0) {
			if (mode == V_ASN1_GENERALIZEDTIME)
				return (-1);
			type = V_ASN1_UTCTIME;
		}
		lt->tm_year += ATOI2(p);		/* yy */
		if (type == V_ASN1_UTCTIME) {
			if (lt->tm_year < 50)
				lt->tm_year += 100;
		}
		lt->tm_mon = ATOI2(p) - 1;		/* mm */
		if (lt->tm_mon < 0 || lt->tm_mon > 11)
			return (-1);
		lt->tm_mday = ATOI2(p);			/* dd */
		if (lt->tm_mday < 1 || lt->tm_mday > 31)
			return (-1);
		lt->tm_hour = ATOI2(p);			/* HH */
		if (lt->tm_hour < 0 || lt->tm_hour > 23)
			return (-1);
		lt->tm_min = ATOI2(p);			/* MM */
		if (lt->tm_min < 0 || lt->tm_min > 59)
			return (-1);
		lt->tm_sec = ATOI2(p);			/* SS */
		/* Leap second 60 is not accepted. Reconsider later? */
		if (lt->tm_sec < 0 || lt->tm_sec > 59)
			return (-1);
		break;
	default:
		return (-1);
	}

	return (type);
}

#endif
