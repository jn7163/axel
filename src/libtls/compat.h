#ifdef CRYPTO_OPENSSL

#include <bsd/stdlib.h>
#include <time.h>

size_t
strlcpy(char *dst, const char *src, size_t dsize);

void *
reallocarray(void *opt, size_t nmemb, size_t size);

void
freezero(void *ptr, size_t size);

int
ASN1_time_tm_clamp_notafter(struct tm *tm);

int
ASN1_time_parse(const char *bytes, size_t len, struct tm *tm, int mode);

#endif
