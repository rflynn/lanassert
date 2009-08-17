/* $Id$ */
/* ex: set ts=2 et: */

#ifndef RULE_H
#define RULE_H

#include <assert.h>
#include "type.h"
#include "prot.h"

/*  */
#define RULE_MAX    64
#define MATCH_MAX   512
#define VAR_MAX     64
#define LIST_MAX    64

enum cmp {
  CMP_NONE = 0,
  CMP_IN,
  CMP_EQL,
  CMP_GT,
  CMP_LT,
  CMP_GTE,
  CMP_LTE,
  CMP_COUNT
};

const char * cmp_to_str(enum cmp);

enum logic {
  LOGIC_NONE = 0,
  LOGIC_AND,
  LOGIC_OR
};

const char * logic_to_str(enum logic);

/* literal data against which a match may be made */
union rule_data {
  struct iplist {
    unsigned len;
    struct ip data[LIST_MAX];
  } ips;
  struct maclist {
    unsigned len;
    struct mac data[LIST_MAX];
  } macs;
  struct intlist {
    unsigned len;
    long data[LIST_MAX];
  } ints;
  struct strlist {
    unsigned len, /* number of valid pointers in str */
             buflen; /* total length of data in buffer */
    unsigned char buf[sizeof(struct ip) * LIST_MAX]; /* buffer where all \0-terminated strings are packed */
    unsigned data[LIST_MAX][2]; /* offset, bytes */
  } strs;
};

void rule_data_init(union rule_data *);
void rule_data_dump(const union rule_data *, enum datatype);

int iplist_init(struct iplist *);
int iplist_append(struct iplist *, const struct ip *);
int iplist_append_str(struct iplist *, const char *);
int iplist_dump(const struct iplist *);
int iplist_in(const struct iplist *, const struct ip *);

int maclist_init(struct maclist *);
int maclist_append(struct maclist *, const struct mac *);
int maclist_append_str(struct maclist *, const char *);
int maclist_dump(const struct maclist *);
int maclist_in(const struct maclist *, const struct mac *);

int intlist_init(struct intlist *);
int intlist_append(struct intlist *, long);
int intlist_append_str(struct intlist *, const char *);
int intlist_dump(const struct intlist *);
int intlist_in(const struct intlist *, long);

int strlist_init(struct strlist *);
int strlist_append(struct strlist *, const char *, size_t);
int strlist_dump(const struct strlist *);
int strlist_in(const struct strlist *, const char *, size_t);

/* a single logical rule which may be part of a larger rule */
struct match_node {
  int is_link; /*  */
  /* link members */
  enum logic logic;
  struct match_node *parent, *left, *right;
  /* match members */
  const struct pktfieldmap *fieldmap;
  int negate; /*  */
  enum cmp op;
  enum datatype datatype;
  union rule_data data;
};

void match_node_init(struct match_node *);
struct match_node * match_node_new(int);
struct match_node * match_add(struct match_node *, const struct match_node *, enum logic);
void match_clear(void);
void match_node_dump_deep(const struct match_node *, int depth);

/* an all-encompassing rule */
struct rule {
  enum pkt pkt;
  enum pkttype type;
  struct match_node *match; /* if this matches... */
  struct match_node *assert; /* then this must also match */
  char name[64];
  char descr[16]; /* TODO: eliminate */
  int pass_break:1, /* if pass, process no more rules for this packet */
      fail_break:1; /* if fail, process no more rules for this packet */
};

void rule_init(struct rule *);
void rule_add(const struct rule *);
void rule_dump(const struct rule *);
void rules_apply(const struct cap *c);
void rules_clear(void);

int match_exec(const struct cap *, const struct rule *, const struct match_node *);

struct var {
  char name[32];
  enum datatype type;
  union rule_data data;
};

int alias_add(const char *name, enum datatype type, const union rule_data *data);
const struct var * alias_lookup(const char *name);
int alias_clear(void);

#endif

