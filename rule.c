/* $Id$ */
/* ex: set ts=2 et: */

/* functions used in constructing and executing rules */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "type.h"
#include "prot.h"
#include "rule.h"
#include "util.h"

extern unsigned Verbose;

static const char *Cmps[] = {
  "(None)",
  "IN",
  "EQL",
  "GT",
  "LT",
  "GTE",
  "LTE",
  "ARGH?!"
};
const char * cmp_to_str(enum cmp c)
{
  return Cmps[c];
}

static const char *Logic[] = {
  "NONE",
  "AND",
  "OR"
};
const char * logic_to_str(enum logic l)
{
  return Logic[l];
}

void rule_data_init(union rule_data *rd)
{
  rd->ips.len = 0;
  rd->macs.len = 0;
  rd->ints.len = 0;
  rd->strs.len = 0;
  rd->strs.buflen = 0;
}

/**
 *
 */
void rule_data_dump(const union rule_data *rd, enum datatype dt)
{
  printf("rule_data( ");
  switch (dt) {
  case TYPE_IP:
    iplist_dump(&rd->ips);
    break;
  case TYPE_MAC:
    maclist_dump(&rd->macs);
    break;
  case TYPE_INT:
    intlist_dump(&rd->ints);
    break;
  case TYPE_NONE:
  default:
    printf("#%d", dt);
    break;
  }
  printf(" )");
}

/**
 *
 */
static struct match_node MatchNodes[MATCH_MAX];
static size_t MatchNodeCnt = 1; /* skip first one, 0 =~ NULL */
struct match_node * match_node_new(int is_link)
{
  struct match_node *n;
  if (MATCH_MAX == MatchNodeCnt) {
    fprintf(stderr, "match_node limit of %u exceeded!\n", MATCH_MAX);
    return NULL;
  }
  n = MatchNodes + MatchNodeCnt++;
  n->is_link = is_link;
  n->logic = (is_link ? LOGIC_OR : LOGIC_NONE);
  return n;
}

void match_node_init(struct match_node *n)
{
  /* init link members */
  n->logic = LOGIC_NONE;
  n->parent = NULL;
  n->left = NULL;
  n->right = NULL;
  /* init match members */
  n->fieldmap = NULL;
  n->negate = 0;
  n->op = CMP_NONE;
  n->datatype = TYPE_NONE;
  rule_data_init(&n->data);
}

/**
 * @note: make a copy of m, as it is not ours
 */
struct match_node * match_add(struct match_node *n, const struct match_node *m, enum logic l)
{
  struct match_node *mc, *nc;
  assert(NULL == n || n->is_link);
  assert(0 == m->is_link);
  if (l == LOGIC_NONE && n && (n->left || n->right)) {
    fprintf(stderr, "must have AND|OR if there are other matches!\n");
    printf("n: "); match_node_dump_deep(n, 0); printf("\n");
    printf("m: "); match_node_dump_deep(m, 0); printf("\n");
  }
  mc = match_node_new(0);
  assert(mc);
  memcpy(mc, m, sizeof *m);
  if (NULL == n) {
    n = match_node_new(1);
    assert(n);
  }
  if (NULL == n->left) {
    n->left = mc;
    n->logic = l;
    mc->parent = n;
    return n;
  } else if (NULL == n->right) {
    n->right = mc;
    n->logic = l;
    mc->parent = n;
    return n;
  } else {
    /* work our way on up until we find another place to attach */
    struct match_node *curr = n;
    while (NULL != curr->right && NULL != curr->parent)
      curr = curr->parent;
    nc = match_node_new(1);
    assert(nc);
    if (NULL == curr->right) { /* attach at right */
      curr->right = nc;
      nc->parent = curr;
    } else { /* create new top node */
#if 1
      struct match_node *link = match_node_new(1);
      assert(link);
      assert(NULL == curr->parent);
      link->left = curr;
      link->right = nc;
      curr->parent = link;
      nc->parent = link;
#     ifdef DEBUG
      printf("link node #%u left:#%u right:#%u\n",
        (unsigned)(link - MatchNodes),
        (unsigned)(link->left - MatchNodes),
        (unsigned)(link->right - MatchNodes));
#     endif
#else
      curr->parent = nc;
      nc->left = curr;
#endif
    }
    return match_add(nc, m, l);
  }
  printf("n: "); match_node_dump_deep(n, 0); printf("\n");
  printf("m: "); match_node_dump_deep(m, 0); printf("\n");
  assert(0);
}

/**
 * reset all matches for a rule re-reading
 */
void match_clear(void)
{
  while (MatchNodeCnt-- > 1)
    match_node_init(MatchNodes + MatchNodeCnt);
}

void match_node_dump_deep(const struct match_node *n, int depth)
{
  int i = depth;
  const char *pkt = NULL, *pktfield = NULL;
  printf("  ");
  while (i--)
    putchar('-');
  printf("> match_node #%2u", (unsigned)(n - MatchNodes));
  if (NULL == n) {
    putchar('\n');
    return;
  }
  if (n->fieldmap)
    pkt = pkt_to_str(n->fieldmap->pkt_id);
  if (n->fieldmap)
    pktfield = n->fieldmap->str;
  printf(
    " link:%d logic:%s"
    " parent:%2u left:%2u right:%2u",
    n->is_link, Logic[n->logic],
    (unsigned)(n->parent ? n->parent - MatchNodes : 0),
    (unsigned)(n->left ? n->left - MatchNodes : 0),
    (unsigned)(n->right ? n->right - MatchNodes : 0));
  if (LOGIC_NONE == n->logic) {
    printf(" fieldmap:%p prot:%s field:%s negate:%d op:%s data: ",
      (void *)n->fieldmap, pkt, pktfield, n->negate, cmp_to_str(n->op));
    rule_data_dump(&n->data, n->datatype);
  }
  printf("\n");
  depth++;
  if (n->left)
    match_node_dump_deep(n->left, depth);
  if (n->right)
    match_node_dump_deep(n->right, depth);
}

/**
 *
 */
static struct rule Rules[RULE_MAX];
static size_t RuleCnt = 0;
static struct rule * rule_new(void)
{
  struct rule *r;
  if (RULE_MAX == RuleCnt) {
    fprintf(stderr, "rule limit of %u exceeded!\n", RULE_MAX);
    return NULL;
  }
  r = Rules + RuleCnt++;
  /* initialize */
  rule_init(r);
  return r;
}

void rule_init(struct rule *r)
{
  r->pkt = UNKNOWN;
  r->type = PKT_NONE;
  r->match = NULL;
  r->assert = NULL;
  r->name[0] = '\0';
  r->descr[0] = '\0';
  r->pass_break = 0;
  r->fail_break = 0;
}

/* TODO: use linked lists instead to save room */
struct rule_pkttype {
  unsigned len;
  unsigned rules[RULE_MAX]; /*  */
} RulesByPktType[PROT_MAX];

/**
 * make a copy of 'r' into Rules
 * @param r a static rule. not ours. must make copy.
 */
void rule_add(const struct rule *r)
{
  struct rule *n;
  struct rule_pkttype *rp;
  n = rule_new();
  if (NULL == n) {
    fprintf(stderr, "Rule limit exceeded. Try upping RULE_MAX higher than %u\n",
      RULE_MAX);
    return;
  }
  memcpy(n, r, sizeof *n);
  if (Verbose > 1)
    rule_dump(n);
  rp = RulesByPktType + n->pkt;
#ifdef DEBUG
  printf("rule_add() n->type: %u\n", n->pkt);
#endif
  rp->rules[rp->len++] = (unsigned)(n - Rules);
}

void rule_dump(const struct rule *r)
{
  printf("rule(%p):\n", (void *)r);
  if (NULL == r)
    return;
  printf(" name:  %s\n", r->name);
  printf(" descr: %s\n", r->descr);
  printf(" type:  %s\n", pkttype_to_str(r->type));
  printf(" match:\n"); match_node_dump_deep(r->match, 0);
  printf(" assert:\n"); match_node_dump_deep(r->assert, 0);
}

/* iplist_() methods */

int iplist_init(struct iplist *l)
{
  l->len = 0;
  return 1;
}

int iplist_append(struct iplist *l, const struct ip *ip)
{
  if (l->len == (unsigned)(sizeof l->data / sizeof l->data[0])) {
    fprintf(stderr, "iplist_append() whoops, l->len=%u!\n", l->len);
    return 0;
  }
  memcpy(l->data + l->len++, ip, sizeof *ip);
  return 1;
}

int iplist_append_str(struct iplist *l, const char *str)
{
  struct ip *ip;
  if (l->len == (unsigned)(sizeof l->data / sizeof l->data[0]))
    return 0;
  ip = l->data + l->len++;
  if (ip_parse(str, ip))
    return 1;
  fprintf(stderr, "ip_parse failed (%s)\n", str);
  l->len--;
  return 0;
}

int iplist_dump(const struct iplist *l)
{
  unsigned i;
  printf("iplist(%u)[ ", l->len);
  for (i = 0; i < l->len; i++) {
    ip_dump(l->data + i);
    printf(" ");
  }
  printf("]");
  fflush(stdout);
  return 1;
}

int iplist_in(const struct iplist *l, const struct ip *key)
{
  unsigned i;
  for (i = 0; i < l->len; i++)
    if (0 == ip_cmp(l->data + i, key))
      return 1;
  return 0;
}

/* maclist_() methods */

int maclist_init(struct maclist *l)
{
  l->len = 0;
  return 1;
}

int maclist_append(struct maclist *l, const struct mac *mac)
{
  if (l->len == (unsigned)(sizeof l->data / sizeof l->data[0]))
    return 0;
  memcpy(l->data + l->len++, mac, sizeof *mac);
  return 1;
}

int maclist_append_str(struct maclist *l, const char *str)
{
  struct mac *mac;
  if (l->len == (unsigned)(sizeof l->data / sizeof l->data[0]))
    return 0;
  mac = l->data + l->len++;
  if (mac_parse(str, mac))
    return 1;
  fprintf(stderr, "mac_parse failed (%s)\n", str);
  l->len--;
  return 0;
}

int maclist_dump(const struct maclist *l)
{
  unsigned i;
  printf("maclist(%u)[ ", l->len);
  for (i = 0; i < l->len; i++) {
    mac_dump(l->data + i);
    printf(" ");
  }
  printf("]");
  fflush(stdout);
  return 1;
}

int maclist_in(const struct maclist *l, const struct mac *key)
{
  unsigned i;
  for (i = 0; i < l->len; i++)
    if (0 == mac_cmp(l->data + i, key))
      return 1;
  return 0;
}


/* intlist_() methods */

int intlist_init(struct intlist *l)
{
  l->len = 0;
  return 1;
}

int intlist_append(struct intlist *l, long i)
{
  if (l->len == (unsigned)(sizeof l->data / sizeof l->data[0]))
    return 0;
  l->data[l->len++] = i;
  return 1;
}

int intlist_append_str(struct intlist *l, const char *str)
{
  long i;
  if (l->len == (unsigned)(sizeof l->data / sizeof l->data[0]))
    return 0;
  errno = 0;
  i = strtol(str, NULL, 10);
  printf("strtol(%s) -> %ld\n", str, i);
  if (errno || LONG_MAX == i || LONG_MIN == i) {
    perror("strtol");
    return 0;
  }
  l->data[l->len++] = i;
  return 1;
}

int intlist_dump(const struct intlist *l)
{
  unsigned i;
  printf("intlist(%u)[ ", l->len);
  for (i = 0; i < l->len; i++) {
    printf("%ld ", l->data[i]);
  }
  printf("]");
  fflush(stdout);
  return 1;
}

int intlist_in(const struct intlist *l, long n)
{
  unsigned i;
  for (i = 0; i < l->len; i++)
    if (l->data[i] == n)
      return 1;
  return 0;
}


/* strlist_() methods */

int strlist_init(struct strlist *l)
{
  l->len = 0;
  l->buflen = 0;
  return 1;
}

int strlist_append(struct strlist *l, const char *s, size_t len)
{
  if (l->len == (unsigned)(sizeof l->data / sizeof l->data[0]))
    return 0; /* too many strings */
  if (l->buflen + len > sizeof l->buf)
    return 0; /* no room in buffer */
  l->data[l->len][0] = l->buflen;
  l->data[l->len][1] = (unsigned)len;
  memcpy(l->buf + l->buflen, s, len);
  l->len++;
  l->buflen += len;
  return 1;
}

int strlist_dump(const struct strlist *l)
{
  unsigned i;
  printf("strlist(%u:%u)[ ", l->len, l->buflen);
  for (i = 0; i < l->len; i++) {
    chars_dump(l->buf + l->data[i][0], l->data[i][1]);
    printf("(%u) ", l->data[i][1]);
  }
  printf("]");
  fflush(stdout);
  return 1;
}

int strlist_in(const struct strlist *l, const char *s, size_t len)
{
  unsigned i;
  /* TODO: O(n), make O(log n) */
  for (i = 0; i < l->len; i++)
    if (len == l->data[i][1]
      && s[0] == l->buf[l->data[i][0]]
      && 0 == memcmp(l->buf + l->data[i][0], s, len)) {
      return 1;
    }
  return 0;
}




/**
 * @param a must be single key
 * @param b must be list
 */
#undef DEBUG_RULE_DATA_MATCH
static int rule_data_match(const struct match_node *m, const union rule_data *a, const union rule_data *b)
{
  int ret;
  if (TYPE_NONE == m->fieldmap->type || CMP_NONE == m->op) {
    fprintf(stderr, "rule_data_match() type:%u, op:%u\n",
      m->fieldmap->type, m->op);
    abort();
  }
  if (CMP_IN == m->op || CMP_EQL == m->op) {
    switch (m->fieldmap->type) {
    default:
      fprintf(stderr, "rule_data_match IN/EQL type %d not handled!\n",
        m->fieldmap->type);
      abort();
      break;
    case TYPE_INT:
      ret = intlist_in(&b->ints, a->ints.data[0]);
      break;
    case TYPE_MAC:
      ret = maclist_in(&b->macs, a->macs.data);
      break;
    case TYPE_IP:
#     ifdef DEBUG_RULE_DATA_MATCH
        printf("does ");
        iplist_dump(&b->ips);
        printf(" contain ");
        ip_dump(a->ips.data);
        printf("? ");
#     endif
      ret = iplist_in(&b->ips, a->ips.data);
#     ifdef DEBUG_RULE_DATA_MATCH
        printf("%s\n", (ret ? "YES!" : "NO!"));
#     endif
      break;
    case TYPE_STRING:
      ret = strlist_in(&b->strs, (char *)(a->strs.buf + a->strs.data[0][0]), a->strs.data[0][1]);
#ifdef DEBUG_RULE_DATA_MATCH
      printf("rule_data_match() strlist_in: (%u)", a->strs.data[0][1]);
      chars_dump(a->strs.buf + a->strs.data[0][0], a->strs.data[0][1]);
      strlist_dump(&b->strs);
      printf(" -> %d\n", ret);
#endif
      break;
    }
  } else {
    int cmp;
    switch (m->fieldmap->type) {
    default:
      fprintf(stderr, "rule_data_match <> type %d not handled!\n",
        m->fieldmap->type);
      abort();
      break;
    case TYPE_INT:
      cmp = int_cmp(a->ints.data, b->ints.data);
      break;
    case TYPE_IP:
      cmp = ip_cmp(a->ints.data, b->ints.data);
      break;
    case TYPE_MAC:
      cmp = ip_cmp(a->ints.data, b->ints.data);
      break;
    }
    switch (m->op) {
    default:
      fprintf(stderr, "rule_data_match <> op %d not handled!\n", m->op);
      abort();
      break;
    case CMP_GT: ret = cmp > 0; break;
    case CMP_LT: ret = cmp < 0; break;
    case CMP_GTE: ret = cmp >= 0; break;
    case CMP_LTE: ret = cmp <= 0; break;
    }
  }
  if (m->negate) {
    ret = !ret;
#ifdef DEBUG_RULE_DATA_MATCH
    printf("NEGATED: %d\n", ret);
#endif
  }
  return ret;
}

/**
 * extract field `field` from p into d
 */
int packet_extract(const struct packet *p, enum pktfield field, union rule_data *d)
{
  struct ip ip;
  struct mac mac;
  /* ip init */
  ip.version = 4;
  ip.maskbits = 32;
  ip.mask[0] = ip.mask[1] = ip.mask[2] = ip.mask[3] = UCHAR_MAX;
  /* mac init */
  switch (field) {
  case FIELD_NONE:
  default:
    return 0;
  /* ETH */
  case FIELD_ETH_SRC:
    memcpy(mac.addr, p->data.eth->h_source, sizeof mac.addr);
    return maclist_append(&d->macs, &mac);
  case FIELD_ETH_DST:
    memcpy(mac.addr, p->data.eth->h_dest, sizeof mac.addr);
    return maclist_append(&d->macs, &mac);
  case FIELD_ETH_TYPE:
    if (!ETH_IS_TYPE(p->data.eth->h_proto)) 
      return 0; /* field represents a length, not a type */
    return intlist_append(&d->ints, p->data.eth->h_proto);
  case FIELD_ETH_LEN:
    if (!ETH_IS_LEN(p->data.eth->h_proto)) 
      return 0; /* field represents type, not a length */
    return intlist_append(&d->ints, p->data.eth->h_proto);
  case FIELD_ETH_TRAILER:
    break;
  case FIELD_ETH_VENDID:
  {
    long l = (p->data.eth->h_source[0] << 16) |
             (p->data.eth->h_source[1] << 8) |
             p->data.eth->h_source[2];
    return intlist_append(&d->ints, l);
  }
    break;
  /* ARP */
  case FIELD_ARP_SRC_MAC:
    memcpy(mac.addr, p->data.arp->ar_sha, sizeof mac.addr);
    return maclist_append(&d->macs, &mac);
  case FIELD_ARP_SRC_IP:
    memcpy(ip.addr.v4, p->data.arp->ar_sip, sizeof ip.addr.v4);
    return iplist_append(&d->ips, &ip);
  case FIELD_ARP_DST_MAC:
    memcpy(mac.addr, p->data.arp->ar_tha, sizeof mac.addr);
    return maclist_append(&d->macs, &mac);
  case FIELD_ARP_DST_IP:
    memcpy(ip.addr.v4, p->data.arp->ar_tip, sizeof ip.addr.v4);
    return iplist_append(&d->ips, &ip);
  /* IP */
  case FIELD_IP_DONTFRAG:
    return intlist_append(&d->ints, !!(p->data.ip->frag_off & IP_DONTFRAG));
  case FIELD_IP_DST:
    memcpy(ip.addr.v4, &p->data.ip->daddr, 4);
    return iplist_append(&d->ips, &ip);
  case FIELD_IP_ID:
    return intlist_append(&d->ints, p->data.ip->id);
  case FIELD_IP_LEN:
    return intlist_append(&d->ints, p->data.ip->ihl << 2);
  case FIELD_IP_MOREFRAG:
    return intlist_append(&d->ints, !!(p->data.ip->frag_off & IP_MOREFRAG));
  case FIELD_IP_PROT:
    return intlist_append(&d->ints, p->data.ip->protocol);
  case FIELD_IP_SRC:
    memcpy(ip.addr.v4, &p->data.ip->saddr, sizeof ip.addr.v4);
    return iplist_append(&d->ips, &ip);
  case FIELD_IP_TOTALLEN:
    return intlist_append(&d->ints, p->data.ip->tot_len);
  /* UDP */
  case FIELD_UDP_SRCPORT:
    return intlist_append(&d->ints, p->data.udp->source);
  case FIELD_UDP_DSTPORT:
    return intlist_append(&d->ints, p->data.udp->dest);
  case FIELD_UDP_LEN:
    return intlist_append(&d->ints, p->data.udp->len);
  case FIELD_UDP_CHKSUM:
    return intlist_append(&d->ints, p->data.udp->check);
  /* ICMP */
  case FIELD_ICMP_TYPE:
    return intlist_append(&d->ints, p->data.icmp->type);
  case FIELD_ICMP_CODE:
    return intlist_append(&d->ints, p->data.icmp->code);
  case FIELD_ICMP_LEN:
    return intlist_append(&d->ints, p->len - 8);
  case FIELD_ICMP_PAYLOAD:
    return strlist_append(&d->strs, (char *)p->data.icmp + 8, p->len - 8);
  /* BOOTP */
  case FIELD_BOOTP_TYPE:
    return intlist_append(&d->ints, p->data.bootp->type);
  case FIELD_BOOTP_CLIENT_IP:
    memcpy(ip.addr.v4, &p->data.bootp->client_ip, sizeof ip.addr.v4);
    return iplist_append(&d->ips, &ip);
  case FIELD_BOOTP_CLIENT_MAC:
    memcpy(mac.addr, p->data.bootp->client_mac, sizeof mac.addr);
    return maclist_append(&d->macs, &mac);
  /* TCP */
  case FIELD_TCP_SRCPORT:
    return intlist_append(&d->ints, p->data.tcp->source);
  case FIELD_TCP_DSTPORT:
    return intlist_append(&d->ints, p->data.tcp->dest);
  case FIELD_TCP_SEQ:
    return intlist_append(&d->ints, p->data.tcp->seq);
  case FIELD_TCP_ACKSEQ:
    return intlist_append(&d->ints, p->data.tcp->ack_seq);
  case FIELD_TCP_WINDOW:
    return intlist_append(&d->ints, p->data.tcp->window);
  case FIELD_TCP_CHKSUM:
    return intlist_append(&d->ints, p->data.tcp->check);
  case FIELD_TCP_URGPTR:
    return intlist_append(&d->ints, p->data.tcp->urg_ptr);
  case FIELD_TCP_FLAG_URG:
    return intlist_append(&d->ints, p->data.tcp->urg);
  case FIELD_TCP_FLAG_ACK:
    return intlist_append(&d->ints, p->data.tcp->ack);
  case FIELD_TCP_FLAG_PSH:
    return intlist_append(&d->ints, p->data.tcp->psh);
  case FIELD_TCP_FLAG_RST:
    return intlist_append(&d->ints, p->data.tcp->rst);
  case FIELD_TCP_FLAG_SYN:
    return intlist_append(&d->ints, p->data.tcp->syn);
  case FIELD_TCP_FLAG_FIN:
    return intlist_append(&d->ints, p->data.tcp->fin);
  /* DNS */
  case FIELD_DNS_Q:
    return intlist_append(&d->ints, p->data.dns->qr);
  case FIELD_DNS_QFLAGS:
    return intlist_append(&d->ints, p->data.dns->opcode);
  case FIELD_DNS_AUTH:
    return intlist_append(&d->ints, p->data.dns->aa);
  case FIELD_DNS_TRUNC:
    return intlist_append(&d->ints, p->data.dns->tc);
  case FIELD_DNS_REC_AVAIL:
    return intlist_append(&d->ints, p->data.dns->ra);
  case FIELD_DNS_RCODE:
    return intlist_append(&d->ints, p->data.dns->rcode);
  case FIELD_DNS_CNT_Q:
    return intlist_append(&d->ints, p->data.dns->q_cnt);
  case FIELD_DNS_CNT_ANS_RR:
    return intlist_append(&d->ints, p->data.dns->ans_rr_cnt);
  case FIELD_DNS_CNT_AUTH_RR:
    return intlist_append(&d->ints, p->data.dns->auth_rr_cnt);
  case FIELD_DNS_CNT_ADD_RR:
    return intlist_append(&d->ints, p->data.dns->add_rr_cnt);
  /* NBNS */
  case FIELD_NBNS_Q:
		return intlist_append(&d->ints, p->data.nbns->q);
  case FIELD_NBNS_OP:
		return intlist_append(&d->ints, p->data.nbns->op);
  case FIELD_NBNS_TRUNC:
		return intlist_append(&d->ints, p->data.nbns->trunc);
  case FIELD_NBNS_RECURSE:
		return intlist_append(&d->ints, p->data.nbns->recurs);
  case FIELD_NBNS_BCAST:
		return intlist_append(&d->ints, p->data.nbns->bcast);
  case FIELD_NBNS_CNT_Q:
		return intlist_append(&d->ints, p->data.nbns->q_cnt);
  case FIELD_NBNS_CNT_ANS_RR:
		return intlist_append(&d->ints, p->data.nbns->ans_rr_cnt);
  case FIELD_NBNS_CNT_AUTH_RR:
		return intlist_append(&d->ints, p->data.nbns->auth_rr_cnt);
  case FIELD_NBNS_CNT_ADD_RR:
		return intlist_append(&d->ints, p->data.nbns->add_rr_cnt);
  /* LLC */
  case FIELD_LLC_DSAP:
    return intlist_append(&d->ints, (long)p->data.llc->dsap);
  case FIELD_LLC_SSAP:
    return intlist_append(&d->ints, (long)p->data.llc->ssap);
  case FIELD_LLC_ORG:
    if (LLC_DSAP_SNAP == p->data.llc->dsap) {
      long l =
          p->data.llc->data.snap.org[0] << 16
        | p->data.llc->data.snap.org[1] << 8
        | p->data.llc->data.snap.org[2] ;
      return intlist_append(&d->ints, l);
    } else {
      return 0;
    }
  case FIELD_LLC_PID:
    return LLC_DSAP_SNAP == p->data.llc->dsap &&
           intlist_append(&d->ints, (long)p->data.llc->data.snap.pid);
  /* CDP */
  case FIELD_CDP_VER:
    return intlist_append(&d->ints, p->data.cdp.ver);
  case FIELD_CDP_TTL:
    return intlist_append(&d->ints, p->data.cdp.ttl);
  case FIELD_CDP_CHKSUM:
    return intlist_append(&d->ints, p->data.cdp.chksum);
  case FIELD_CDP_DEVID:
  {
    const struct cdpnode *n = p->data.cdp.node + p->data.cdp.node_idx[CDP_TYPE_DEVID];
    return n != p->data.cdp.node
      && strlist_append(&d->strs, n->data.dev.id, n->data.dev.len);
  }
  case FIELD_CDP_PORT:
  {
    const struct cdpnode *n = p->data.cdp.node + p->data.cdp.node_idx[CDP_TYPE_PORTID];
    return n != p->data.cdp.node
      && strlist_append(&d->strs, n->data.port.iface, n->data.port.len);
  }
  case FIELD_CDP_SOFTWARE:
  {
    const struct cdpnode *n = p->data.cdp.node + p->data.cdp.node_idx[CDP_TYPE_SOFTWARE];
    return n != p->data.cdp.node
      && strlist_append(&d->strs, n->data.soft.ver, n->data.soft.len);
  }
  case FIELD_CDP_PLATFORM:
  {
    const struct cdpnode *n = p->data.cdp.node + p->data.cdp.node_idx[CDP_TYPE_PLATFORM];
    return n != p->data.cdp.node
      && strlist_append(&d->strs, n->data.plat.form, n->data.plat.len);
  }
  /* NBDGM */
  case FIELD_NBDGM_TYPE:
    return intlist_append(&d->ints, p->data.nbdgm.head->type);
  case FIELD_NBDGM_NODETYPE:
    return intlist_append(&d->ints, p->data.nbdgm.head->node_type);
  case FIELD_NBDGM_FIRSTFRAG:
    return intlist_append(&d->ints, p->data.nbdgm.head->first_frag);
  case FIELD_NBDGM_MOREFRAG:
    return intlist_append(&d->ints, p->data.nbdgm.head->more_frag);
  case FIELD_NBDGM_SRCPORT:
    return intlist_append(&d->ints, p->data.nbdgm.head->srcport);
  case FIELD_NBDGM_LEN:
    return intlist_append(&d->ints, p->data.nbdgm.head->len);
  case FIELD_NBDGM_SRCNAME:
    return strlist_append(&d->strs, p->data.nbdgm.srcname, strlen(p->data.nbdgm.srcname));
  case FIELD_NBDGM_DSTNAME:
    return strlist_append(&d->strs, p->data.nbdgm.dstname, strlen(p->data.nbdgm.dstname));
  /* SNMP */
  /* IP6 */
  case FIELD_IP6_VER:
    return intlist_append(&d->ints, p->data.ip6->ver);
  case FIELD_IP6_TRAFCLASS:
    return intlist_append(&d->ints, p->data.ip6->trafclass);
  case FIELD_IP6_FLOWLBL:
    return intlist_append(&d->ints, p->data.ip6->flow);
  case FIELD_IP6_PAYLEN:
    return intlist_append(&d->ints, p->data.ip6->paylen);
  case FIELD_IP6_NEXTHDR:
    return intlist_append(&d->ints, p->data.ip6->nexthdr);
  case FIELD_IP6_HOPLIM:
    return intlist_append(&d->ints, p->data.ip6->hoplim);
  case FIELD_IP6_SRC:
    ip.version = 6;
    ip.maskbits = 128;
    ip.mask[4] = ip.mask[5] = ip.mask[6] = ip.mask[7] =
    ip.mask[8] = ip.mask[9] = ip.mask[10] = ip.mask[11] =
    ip.mask[12] = ip.mask[13] = ip.mask[14] = ip.mask[15] = UCHAR_MAX;
    memcpy(ip.addr.v6, &p->data.ip6->src, sizeof ip.addr.v6);
    return iplist_append(&d->ips, &ip);
  case FIELD_IP6_DST:
    ip.version = 6;
    ip.maskbits = 128;
    ip.mask[4] = ip.mask[5] = ip.mask[6] = ip.mask[7] =
    ip.mask[8] = ip.mask[9] = ip.mask[10] = ip.mask[11] =
    ip.mask[12] = ip.mask[13] = ip.mask[14] = ip.mask[15] = UCHAR_MAX;
    memcpy(ip.addr.v6, &p->data.ip6->dst, sizeof ip.addr.v6);
    return iplist_append(&d->ips, &ip);
  /* IGMP */
  } /* end switch */
  fprintf(stderr, "%s:%u: shouldn't happen\n", __FILE__, __LINE__);
  abort(); /* if we screw up, let's find out ASAP */
  return 0;
}

/**
 * does a captured packet match a match_node tree?
 */
int match_exec(const struct cap *c, const struct rule *r, const struct match_node *m)
{
  if (m->is_link) {
    int left, right;
    left = (NULL != m->left && match_exec(c, r, m->left));
    if (left && LOGIC_OR == m->logic)
      return 1;
    else if (!left && LOGIC_AND == m->logic)
      return 0;
    right = (NULL != m->right && match_exec(c, r, m->right));
    return right;
  } else { /* raw data match */
    union rule_data rd;
    const struct packet *p;
    int ret;
    if (0 == c->prots[r->pkt]) {
#ifdef DEBUG
      printf("packet type (%u) not present\n", r->pkt);
#endif
      return 0; /* packet type not present */
    }
    if (NULL == m->fieldmap)
      return 1; /* if the field match is empty, the rule is true */
    p = c->pkt + c->prots[m->fieldmap->pkt_id]; /* point to packet type we want to match */
    rule_data_init(&rd);
    if (!packet_extract(p, m->fieldmap->id, &rd)) {
#ifdef DEBUG
      printf("!packet_extract field=%u\n", m->fieldmap->id);
#endif
      return 0;
    }
    ret = rule_data_match(m, &rd, &m->data);
    if (0 == ret) {
#if 0 /* why didn't this match? */
      printf("!rule_data_match type=%u, cmp=%u, negate=%u\n",
        m->fieldmap->type, m->op, m->negate);
      printf("packet data: ");
      rule_data_dump(&rd, m->fieldmap->type);
      printf("\nrule data:   ");
      rule_data_dump(&m->data, m->fieldmap->type);
      printf("\n");
#endif
    }
    return ret;
  }
  abort();
  return 0;
}

/**
 * apply rules to a parsed packet
 * @param c parsed packet
 */
void rules_apply(const struct cap *c)
{
  int rule_check[RULE_MAX];
  struct rule_pkttype *rp;
  unsigned i, j, r;
  for (i = 0; i < sizeof rule_check / sizeof rule_check[0]; i++)
    rule_check[i] = 0;
  for (i = 1; i < c->pkt_cnt; i++) { /* skip logic packet */
    rp = RulesByPktType + c->pkt[i].pkt;
    for (j = 0; j < rp->len; j++) {
      r = rp->rules[j];
      if (rule_check[r])
        continue; /* no rules to match this type */
      if (!pkttype_match(Rules[r].type, c->pkt + i))
        continue; /* pkt type does not match */
      rule_check[r] = 1;
      if (!match_exec(c, Rules + r, Rules[r].match)) {
#if 0 || defined DEBUG
        printf("frame %lu did not match rule %u\n",
          c->pkt[0].data.logic.frame, r);
        rule_dump(Rules + r);
#endif
        continue;
      }
      if (!match_exec(c, Rules + r, Rules[r].assert)) {
        printf("FAIL %s\n", Rules[r].name);
        cap_dump(c);
      /* TODO: add a cmdline switch to print passes just for kicks */
#if 0 && defined DEBUG
      } else {
        printf("%04d-%02d-%02d %02d:%02d:%02d.%03d frame %9lu PASS %s\n",
          1900 + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday,
          tm->tm_hour, tm->tm_min, tm->tm_sec,
          c->header->ts.tv_usec / 1000,
          c->pkt[0].data.logic.frame, Rules[r].name);
#endif
        if (Rules[r].fail_break)
          break;
      } else if (Rules[r].pass_break)
          break;
    }
  }
}

/**
 * reset all rule structures in anticipation of a re-reading of a ruleset
 */
void rules_clear(void)
{
  unsigned i;
  RuleCnt = 0;
  for (i = 0; i < (unsigned)(sizeof RulesByPktType / sizeof RulesByPktType[0]); i++)
    RulesByPktType[i].len = 0;
  match_clear();
  alias_clear();
}

static struct var Vars[VAR_MAX];
static unsigned VarCnt = 0;

/**
 * @note fails if variable with same name exists
 */
int alias_add(const char *name, enum datatype type, const union rule_data *data)
{
  struct var *v;
  if (NULL != alias_lookup(name)) {
    fprintf(stderr, "ALIAS '%s' already exists.\n", name);
    exit(EXIT_FAILURE);
  }
  if (VarCnt == (unsigned)(sizeof Vars / sizeof Vars[0])) {
    fprintf(stderr, "Maximum alias count reached (%u). Modify ALIAS_MAX.\n", VarCnt);
    return 0;
  }
  v = Vars + VarCnt++;
  strlcpy(v->name, name, sizeof v->name);
  v->type = type;
  memcpy(&v->data, data, sizeof *data);
  return 1;
}

/**
 * FIXME: O(n) when we could be at O(log n) with little effort. but then, this
 * is a one-time thing at startup, and I (naievely) don't expect to have thousands
 * of variables
 */
const struct var * alias_lookup(const char *name)
{
  unsigned i;
  for (i = 0; i < VarCnt; i++)
    if (0 == strcmp(Vars[i].name, name))
      return Vars + i;
  return NULL;
}

int alias_clear(void)
{
  VarCnt = 0;
  return 1;
}


