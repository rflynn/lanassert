/* $Id$ */
/* ex: set ts=2 et: */

#ifndef TYPE_H
#define TYPE_H

#include <linux/if_ether.h>

/* all possible */
enum datatype {
  TYPE_NONE = 0,
  TYPE_IP,
  TYPE_MAC,
  TYPE_INT, /* generic integer */
  TYPE_STRING,
  TYPE_COUNT
};

const char * datatype_to_str(enum datatype);

/**
 * an ethernet address
 */
struct mac {
	unsigned char addr[ETH_ALEN];
};

int mac_parse(const char *, struct mac *);
int mac_to_str(char *, const struct mac *, size_t);
void mac_dump(const struct mac *);
int mac_cmp(const void *, const void *);

/**
 * an IP address
 */
struct ip {
	int version;
  int maskbits;
	unsigned char mask[16]; /* */
	union {
		unsigned char v6[16];
		unsigned char v4[4];
	} addr;
};

int ip_parse(const char *, struct ip *);
int ip_to_str(char *, const struct ip *, size_t, int);
void ip_dump(const struct ip *);
int ip_cmp(const void *, const void *);

int port_cmp(const void *, const void *);
int int_cmp(const void *, const void *);
int str_cmp(const void *, const void *);

#endif

