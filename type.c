/* $Id$ */
/* ex: set ts=2 et: */

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "type.h"

static const char * DataTypeStr[] = {
  "(None)",
  "IP",
  "MAC",
  "INT",
  "STR",
  "COUNT?!"
};

const char * datatype_to_str(enum datatype d)
{
  return DataTypeStr[d];
}

int mac_parse(const char *str, struct mac *mac)
{
  unsigned d[6];
  signed scan;
  scan = sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
    d + 0, d + 1, d + 2, d + 3, d + 4, d + 5);
  if (scan != 6)
    return 0;
  while (scan--)
    mac->addr[scan] = (unsigned char)d[scan];
  return 1;
}

int mac_to_str(char *buf, const struct mac *mac, size_t buflen)
{
  sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
    (int)mac->addr[0], (int)mac->addr[1], (int)mac->addr[2],
    (int)mac->addr[3], (int)mac->addr[4], (int)mac->addr[5]);
  return 1;
}

void mac_dump(const struct mac *mac)
{
  printf("mac(%02x:%02x:%02x:%02x:%02x:%02x)",
    (int)mac->addr[0], (int)mac->addr[1], (int)mac->addr[2],
    (int)mac->addr[3], (int)mac->addr[4], (int)mac->addr[5]);
  fflush(stdout);
}

int mac_cmp(const void *va, const void *vb)
{
  const struct mac *a = va, *b = vb;
  /* sneaky shortcut tricks to avoid call to memcmp(), i figure we require */
  /* uintNN_t anyways, so what the hell */
  uint32_t a4 = *(unsigned long *)a->addr;
  uint32_t b4 = *(unsigned long *)b->addr;
  if (a4 != b4)
    return (a4 > b4 ? 1 : -1);
  return memcmp(a->addr, b->addr, sizeof a->addr);
}

int ip_parse(const char *str, struct ip *ip)
{
  unsigned d[4], mask = 32, m;
  signed scan;
  scan = sscanf(str, "%u.%u.%u.%u/%u",
    d + 0, d + 1, d + 2, d + 3, &mask);
  if (scan < 4) /* omitted mask defaults to full mask */
    return 0;
  ip->version = 4;
  ip->maskbits = mask;
  scan = 4;
  while (scan--) {
    m = mask;
    if (m > CHAR_BIT) m = CHAR_BIT;
    ip->mask[3 - scan] = 0xFF - ((1 << (8 - m)) - 1); /* set octet mask */
    ip->addr.v4[scan] = (unsigned char)d[scan]; /* set octet addr */
    mask -= m;
  }
  return 1;
}

int ip_to_str(char *buf, const struct ip *ip, size_t buflen, int with_mask)
{
  int len = sprintf(buf, "%u.%u.%u.%u",
    (unsigned)ip->addr.v4[0], (unsigned)ip->addr.v4[1],
    (unsigned)ip->addr.v4[2], (unsigned)ip->addr.v4[3]);
  if (with_mask)
    sprintf(buf + len, "/%u", ip->maskbits);
  return 1;
}

void ip_dump(const struct ip *ip)
{
  printf("ip(%u.%u.%u.%u/%u)",
    (unsigned)ip->addr.v4[0], (unsigned)ip->addr.v4[1],
    (unsigned)ip->addr.v4[2], (unsigned)ip->addr.v4[3],
    ip->maskbits);
  fflush(stdout);
}

/* TODO: IPv6 support */
#undef DEBUG_IP_CMP
int ip_cmp(const void *va, const void *vb)
{
  struct ip *a = (struct ip *)va, *b = (struct ip *)vb;
  unsigned i, max = 4;
  unsigned char *mask;
  /* choose loosest mask */
  mask = (a->maskbits < b->maskbits ? a->mask : b->mask);
  for (i = 0; i < 4 && mask[i]; i++) {
    if ((a->addr.v4[i] & mask[i]) != (b->addr.v4[i] & mask[i])) {
#ifdef DEBUG_IP_CMP
      printf("%u: %u & 0x%02X != %u & 0x%02X (mask=%02X.%02X.%02X.%02X)\n",
        i, a->addr.v4[i], mask[i], b->addr.v4[i], mask[i],
        mask[0], mask[1], mask[2], mask[3]);
#endif
      return (int)(a->addr.v4[i] - b->addr.v4[i]);
    }
  }
#ifdef DEBUG_IP_CMP
  printf("MATCH: ");
  ip_dump(a);
  printf(" == ");
  ip_dump(b);
  printf(" (mask=%02X.%02X.%02X.%02X)\n",
    mask[0], mask[1], mask[2], mask[3]);
#endif
  return 0;
}

int port_cmp(const void *va, const void *vb)
{
  const unsigned short *a = va, *b = vb;
  return (*a > *b ? 1 : (*b > *a ? -1 : 0));
}

int int_cmp(const void *va, const void *vb)
{
  const unsigned *a = va, *b = vb;
  return (*a > *b ? 1 : (*b > *a ? -1 : 0));
}

int str_cmp(const void *va, const void *vb)
{
  return strcmp((const char *)va, (const char *)vb);
}

