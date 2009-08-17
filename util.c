/* $Id$ */
/* ex: set ts=2 et: */

#include <ctype.h> /* is*() */
#include <errno.h>
#include <stddef.h> /* size_t */
#include <stdio.h>
#include <stdlib.h>


/**
 *
 */
size_t strlcpy(char *dst, const char *src, size_t size)
{
  char *orig = dst;
  if (0 == size)
    return 0;
  while (*src != '\0' && --size > 0)
    *dst++ = *src++;
  *dst = '\0';
  if (*src != '\0') 
    errno = -1;
  return (size_t)(dst - orig);
}

/**
 * sane OpenBSD str concatenation
 */
size_t strlcat(char *dst, const char *src, size_t size)
{
  char *orig = dst;
  if (0 == size)
    return 0;
  size--;  
  while (*dst != '\0' && size-- > 0) 
    dst++;
  if (size <= 0) {
    errno = -1;
  } else {
    while (*src != '\0' && size-- > 0)
      *dst++ = *src++;
    *dst = '\0';
    if (*src != '\0') 
      errno = -1;
  }
  return (size_t)(dst - orig);
}

/**
 * dump straight-up hex bytes
 */
void bytes_dump(const unsigned char *buf, size_t len)
{
  for (; len; len--, buf++)
    printf("\\x%02X", *buf);
}

/**
 * dump plaintext where possible, hex bytes where not
 */
void chars_dump(const unsigned char *buf, size_t len)
{
  for (; len; len--, buf++)
    printf((isalnum((int)*buf) || ispunct((int)*buf) ? "%c" : "\\x%02X"), *buf);
}

/**
 * process escape characters in string. resulting string may be the same
 * length or shorter.
 * @return length of new string
 * @note assume 
 */
size_t strlunescape(char *w, const char *r, size_t len)
{
  const char *orig = w;
  if (0 == len)
    return 0;
  while (*r != '\0' && --len > 0) {
    *w = *r;
    if ('"' == *r)
      break;
    w++;
    if ('\\' != *r++)
      continue;
    w--;
    switch (*r) {
    case '"': *w++ = '"';  r++; break;
    case '\\':*w++ = '\\'; r++; break;
    case 'b': *w++ = '\b'; r++; break;
    case 'f': *w++ = '\f'; r++; break;
    case 'n': *w++ = '\n'; r++; break;
    case 'r': *w++ = '\r'; r++; break;
    case 't': *w++ = '\t'; r++; break;
    case 'v': *w++ = '\v'; r++; break;
    default: break;
    }
  }
  *w = '\0';
  return (size_t)(w - orig);
}

/**
 * format an IP address into a human-readable string
 * @return pointer to static buffer containing formatted IP addr
 */
const char * ip_addr_to_str(char *buf, size_t buflen, int type, const unsigned char *addr)
{
  buf[0] = '\0';
  if (4 == type) {
    sprintf(buf, "%u.%u.%u.%u",
      addr[0], addr[1], addr[2], addr[3]);
    return buf;
  } else if (6 == type) {
    /* canonicalized IPv6 */
    unsigned i, in_zero = 0, seen_zero = 0, post_zero = 0;
    size_t off;
    for (i = 0, off = 0; i < 16; i+=2) {
      /* two bytes at a time, compress zeroes */
      in_zero = (0 == addr[i] && (0 == seen_zero || (1 == in_zero && 1 == seen_zero)));
      if (!seen_zero && in_zero)
        seen_zero = 1;
      /* if we have just exited a series of 0s, print an extra ":" */
      if (!in_zero && !post_zero && seen_zero) {
        strlcat(buf, ":", buflen), off++;
        post_zero = 1;
      }
      /* ":" separator, assuming we're not currently in a series of 0s */
      if ((i > 0 && !in_zero) || (0 == i && in_zero))
        strlcat(buf, ":", buflen), off++;
      /* ISATAP -- ::0:5efe:W.X.Y.Z -- IPv4 embedded in IPv6 */
      if (12 == i
       && '\x00' == addr[8]
       && '\x00' == addr[9]
       && '\x5e' == addr[10]
       && (unsigned char)'\xfe' == addr[11]) {
        sprintf(buf + off, "%u.%u.%u.%u", addr[12], addr[13], addr[14], addr[15]);
        break; /* we're done */
      }
      if (in_zero)
        continue;
      /* 2 bytes at once, lowercase, if not in a series of 0s */
#if 0
      if (0 == ip->addr.v6[i]) {
        if (0 == ip->addr.v6[i + 1]) {
          strlcat(buf, "0", buflen), off++;
        } else {
          off += sprintf(buf + off, "%x", addr[i + 1]);
        }
      } else
#endif
        off += sprintf(buf + off, "%x", ((addr[i] << 8) | addr[i + 1]));
    } /* for */
    if (17 == i && in_zero && !post_zero && '\0' == addr[0])
      strlcat(buf, ":", buflen);
  } else {
    fprintf(stderr, "ip_addr_to_str() type=%d?!\n", type);
    abort();
  }
  return buf;
}

/**
 * decode a MSFT NetBIOS-encoded string
 */
void msft_decode(char *dst, const char *src, size_t len)
{
  if (' ' == *src)
    src++, len--; /* skip initial 20(?) */
  while (len > 2 && *src && *(src + 1)) {
    *dst = ((*src - 'A') << 4) | (*(src + 1) - 'A');
    if ('\x20' == *dst)
      break; /* break on subsequent space(?) */
    dst++;
    src += 2;
    len -= 2;
  }
  *dst = '\0';
}




