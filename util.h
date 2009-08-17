/* $Id$ */
/* ex: set ts=2 et: */
/* generic helper functions */

#include <stddef.h>

void bytes_dump(const unsigned char *, size_t);
void chars_dump(const unsigned char *, size_t);

/* OpenBSD's excellent, sane, safe, string functions */
size_t strlcpy(char *, const char *, size_t);
size_t strlcat(char *, const char *, size_t);

size_t strlunescape(char *, const char *, size_t);

const char * ip_addr_to_str(char *buf, size_t buflen, int type, const unsigned char *addr);

void msft_decode(char *dst, const char *src, size_t len);

