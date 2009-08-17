/* $Id$ */
/* ex: set ts=2 et: */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "prot.h"
#include "util.h"

extern int Verbose;

/**
 * the more common Ethernet types
 */
static const struct eth_prot {
  uint16_t id;
  const char descr[30];
} Eth_Prot[] = {
  /*id      descr */
  { 0x0060, "Loopback"          },
  { 0x0200, "PUP"               },
  { 0x0201, "PUP Addr Trans"    },
  { 0x0800, "IP"                },
  { 0x0805, "CCITT X.25"        },
  { 0x0806, "ARP"               },
  { 0x8035, "RARP"              },
  { 0x809b, "AppleTalk DDP"     },
  { 0x80f3, "AppleTalk AARP"    },
  { 0x8100, "802.1Q VLAN Extended Header" },
  { 0x8137, "IPX over DIX"      },
  { 0x86dd, "IPv6 over bluebook" },
  { 0x8781, "Symbol Mobile Roaming" },
  { 0x8863, "PPPoE discovery"   },
  { 0x8864, "PPPoE session"     },
  { 0x88a2, "ATAoE"             },
  { 0x9000, "Loopback"          },
};

static int eth_prot_cmp(const void *va, const void *vb)
{
  const struct eth_prot *a = va, *b = vb;
  return (a->id > b->id ? 1 : (b->id > a->id ? -1 : 0));
}

const char * eth_prot_by_id(uint16_t id)
{
  const struct eth_prot *res;
  struct eth_prot key;
  key.id = id;
  res = bsearch(&key, Eth_Prot, sizeof Eth_Prot / sizeof Eth_Prot[0], sizeof Eth_Prot[0], eth_prot_cmp);
  if (NULL == res)
    return "?";
  return res->descr;
}


/**
 * O(log n) "prot.field" -> { prot, field_id }
 * @note MUST be in ascending alpha order by str!
 */
static const struct pkttype_match PktTypes[] = {
  /* str                pkt     type */
  { "ARP:REQ",          ARP,    PKT_ARP_REQ       },
  { "ARP:RESP",         ARP,    PKT_ARP_RESP      },
  { "BOOTP",            BOOTP,  PKT_BOOTP         },
  { "BOOTP:REQ",        BOOTP,  PKT_BOOTP_REQ     },
  { "BOOTP:RESP",       BOOTP,  PKT_BOOTP_RESP    },
  { "CDP",              CDP,    PKT_CDP           },
  { "DNS",              DNS,    PKT_DNS           },
  { "DNS:REQ",          DNS,    PKT_DNS_REQ       },
  { "DNS:RESP",         DNS,    PKT_DNS_RESP      },
  { "ETH",              ETH,    PKT_ETH           },
  { "ICMP",             ICMP,   PKT_ICMP          },
  { "IP",               IP,     PKT_IP            },
  { "IP4",              IP,     PKT_IP            },
  { "IP6",              IP6,    PKT_IP6           },
  { "LLC",              LLC,    PKT_LLC           },
  { "LLC:SNAP",         LLC,    PKT_LLC_SNAP      },
  { "NBDGM",            NBDGM,  PKT_NBDGM         },
  { "NBNS",             NBNS,   PKT_NBNS          },
  { "NBNS:QUERY",       NBNS,   PKT_NBNS_QUERY    },
  { "NBNS:REFRESH",     NBNS,   PKT_NBNS_REFRESH  },
  { "NBNS:REGISTER",    NBNS,   PKT_NBNS_REGISTER },
  { "NBNS:RELEASE",     NBNS,   PKT_NBNS_RELEASE  },
  { "NBNS:REQ",         NBNS,   PKT_NBNS_REQ      },
  { "NBNS:RESP",        NBNS,   PKT_NBNS_RESP     },
  { "NBNS:WACK",        NBNS,   PKT_NBNS_WACK     },
  { "SNMP",             SNMP,   PKT_SNMP,         },
  { "STP",              STP,    PKT_STP           },
  { "TCP",              TCP,    PKT_TCP           },
  { "TCP:FIN",          TCP,    PKT_TCP_FIN       },
  { "TCP:RST",          TCP,    PKT_TCP_RST       },
  { "TCP:SYN",          TCP,    PKT_TCP_SYN       },
  { "UDP",              UDP,    PKT_UDP           },
};

/**
 * O(log n) "prot.field" -> { prot, field_id }
 * @note MUST be in ascending alpha order
 */
static const struct pktfieldmap PktFieldMap[] = {
  /*str                 pkt       id                    type */
  /* ARP */
  { "ARP.DST.IP",       ARP,      FIELD_ARP_DST_IP,     TYPE_IP     },
  { "ARP.DST.MAC",      ARP,      FIELD_ARP_DST_MAC,    TYPE_MAC    },
  { "ARP.SRC.IP",       ARP,      FIELD_ARP_SRC_IP,     TYPE_IP     },
  { "ARP.SRC.MAC",      ARP,      FIELD_ARP_SRC_MAC,    TYPE_MAC    },
  /* BOOTP */
  { "BOOTP.CLIENT.IP",  BOOTP,    FIELD_BOOTP_TYPE,     TYPE_IP     },
  { "BOOTP.CLIENT.MAC", BOOTP,    FIELD_BOOTP_TYPE,     TYPE_MAC    },
  { "BOOTP.TYPE",       BOOTP,    FIELD_BOOTP_TYPE,     TYPE_INT    },
  /* CDP */
  { "CDP.CHKSUM",       CDP,      FIELD_CDP_CHKSUM,     TYPE_INT    },
  { "CDP.DEVID",        CDP,      FIELD_CDP_DEVID,      TYPE_STRING },
  { "CDP.PLATFORM",     CDP,      FIELD_CDP_PLATFORM,   TYPE_INT    },
  { "CDP.PORT",         CDP,      FIELD_CDP_PORT,       TYPE_INT    },
  { "CDP.SOFTWARE",     CDP,      FIELD_CDP_SOFTWARE,   TYPE_INT    },
  { "CDP.TTL",          CDP,      FIELD_CDP_TTL,        TYPE_INT    },
  { "CDP.VER",          CDP,      FIELD_CDP_VER,        TYPE_INT    },
  /* DNS */
  { "DNS.AUTH",         DNS,      FIELD_DNS_AUTH,       TYPE_INT    },
  { "DNS.CNT.Q",        DNS,      FIELD_DNS_CNT_Q,      TYPE_INT    },
  { "DNS.CNT.ANS_RR",   DNS,      FIELD_DNS_CNT_ANS_RR, TYPE_INT    },
  { "DNS.CNT.AUTH_RR",  DNS,      FIELD_DNS_CNT_AUTH_RR,TYPE_INT    },
  { "DNS.CNT.ADD_RR",   DNS,      FIELD_DNS_CNT_ADD_RR, TYPE_INT    },
  { "DNS.Q",            DNS,      FIELD_DNS_Q,          TYPE_INT    },
  { "DNS.QFLAGS",       DNS,      FIELD_DNS_QFLAGS,     TYPE_INT    },
  { "DNS.RCODE",        DNS,      FIELD_DNS_RCODE,      TYPE_INT    },
  { "DNS.REC_AVAIL",    DNS,      FIELD_DNS_REC_AVAIL,  TYPE_INT    },
  { "DNS.TRUNC",        DNS,      FIELD_DNS_TRUNC,      TYPE_INT    },
  /* ETH */
  { "ETH.DST",          ETH,      FIELD_ETH_DST,        TYPE_MAC    },
  { "ETH.LEN",          ETH,      FIELD_ETH_LEN,        TYPE_INT    },
  { "ETH.SRC",          ETH,      FIELD_ETH_SRC,        TYPE_MAC    },
  { "ETH.TRAILER",      ETH,      FIELD_ETH_TRAILER,    TYPE_STRING },
  { "ETH.TYPE",         ETH,      FIELD_ETH_TYPE,       TYPE_INT    },
  { "ETH.VENDID",       ETH,      FIELD_ETH_VENDID,     TYPE_INT    },
  /* ICMP */
  { "ICMP.CODE",        ICMP,     FIELD_ICMP_CODE,      TYPE_INT    },
  { "ICMP.LEN",         ICMP,     FIELD_ICMP_LEN,       TYPE_INT    },
  { "ICMP.PAYLOAD",     ICMP,     FIELD_ICMP_PAYLOAD,   TYPE_STRING },
  { "ICMP.TYPE",        ICMP,     FIELD_ICMP_TYPE,      TYPE_INT    },
  /* IP */
  { "IP.DONTFRAG",      IP,       FIELD_IP_DONTFRAG,    TYPE_INT    },
  { "IP.DST",           IP,       FIELD_IP_DST,         TYPE_IP     },
  { "IP.ID",            IP,       FIELD_IP_ID,          TYPE_INT    },
  { "IP.LEN",           IP,       FIELD_IP_LEN,         TYPE_INT    },
  { "IP.MOREFRAG",      IP,       FIELD_IP_MOREFRAG,    TYPE_INT    },
  { "IP.PROT",          IP,       FIELD_IP_PROT,        TYPE_INT    },
  { "IP.SRC",           IP,       FIELD_IP_SRC,         TYPE_IP     },
  { "IP.TOTALLEN",      IP,       FIELD_IP_TOTALLEN,    TYPE_INT    },
  { "IP.TTL",           IP,       FIELD_IP_TTL,         TYPE_INT    },
  /* IP6 */
  { "IP6.DST",          IP6,      FIELD_IP6_DST,        TYPE_IP     },
  { "IP6.FLOWLBL",      IP6,      FIELD_IP6_FLOWLBL,    TYPE_INT    },
  { "IP6.HOPLIM",       IP6,      FIELD_IP6_HOPLIM,     TYPE_INT    },
  { "IP6.NEXTHDR",      IP6,      FIELD_IP6_NEXTHDR,    TYPE_INT    },
  { "IP6.PAYLEN",       IP6,      FIELD_IP6_PAYLEN,     TYPE_INT    },
  { "IP6.SRC",          IP6,      FIELD_IP6_SRC,        TYPE_IP     },
  { "IP6.TRAFCLASS",    IP6,      FIELD_IP6_TRAFCLASS,  TYPE_INT    },
  { "IP6.VER",          IP6,      FIELD_IP6_VER,        TYPE_INT    },
  /* LLC */
  { "LLC.DSAP",         LLC,      FIELD_LLC_DSAP,       TYPE_INT    },
  { "LLC.ORG",          LLC,      FIELD_LLC_ORG,        TYPE_INT    },
  { "LLC.PID",          LLC,      FIELD_LLC_PID,        TYPE_INT    },
  { "LLC.SSAP",         LLC,      FIELD_LLC_SSAP,       TYPE_INT    },
  /* NBDGM */
  { "NBDGM.DSTNAME",    NBDGM,    FIELD_NBDGM_DSTNAME,  TYPE_STRING },
  { "NBDGM.FIRSTFRAG",  NBDGM,    FIELD_NBDGM_FIRSTFRAG,TYPE_INT    },
  { "NBDGM.LEN",        NBDGM,    FIELD_NBDGM_LEN,      TYPE_INT    },
  { "NBDGM.MOREFRAG",   NBDGM,    FIELD_NBDGM_MOREFRAG, TYPE_INT    },
  { "NBDGM.NODETYPE",   NBDGM,    FIELD_NBDGM_NODETYPE, TYPE_INT    },
  { "NBDGM.SRCNAME",    NBDGM,    FIELD_NBDGM_SRCNAME,  TYPE_STRING },
  { "NBDGM.SRCPORT",    NBDGM,    FIELD_NBDGM_SRCPORT,  TYPE_INT    },
  { "NBDGM.TYPE",       NBDGM,    FIELD_NBDGM_TYPE,     TYPE_INT    },
  /* NBNS */
  { "NBNS.BCAST",       NBNS,     FIELD_NBNS_BCAST,     TYPE_INT    },
  { "NBNS.CNT.ADD_RR",  NBNS,     FIELD_NBNS_CNT_ADD_RR,TYPE_INT    },
  { "NBNS.CNT.ANS_RR",  NBNS,     FIELD_NBNS_CNT_ANS_RR,TYPE_INT    },
  { "NBNS.CNT.AUTH_RR", NBNS,     FIELD_NBNS_CNT_AUTH_RR,TYPE_INT   },
  { "NBNS.CNT.Q",       NBNS,     FIELD_NBNS_CNT_Q,     TYPE_INT    },
  { "NBNS.OP",          NBNS,     FIELD_NBNS_OP,        TYPE_INT    },
  { "NBNS.Q",           NBNS,     FIELD_NBNS_Q,         TYPE_INT    },
  { "NBNS.RECURSE",     NBNS,     FIELD_NBNS_RECURSE,   TYPE_INT    },
  { "NBNS.TRUNC",       NBNS,     FIELD_NBNS_TRUNC,     TYPE_INT    },
  /* TCP */
  { "TCP.ACKSEQ",       TCP,      FIELD_TCP_ACKSEQ,     TYPE_INT    },
  { "TCP.CHKSUM",       TCP,      FIELD_TCP_CHKSUM,     TYPE_INT    },
  { "TCP.DSTPORT",      TCP,      FIELD_TCP_DSTPORT,    TYPE_INT    },
  { "TCP.FLAG.ACK",     TCP,      FIELD_TCP_FLAG_ACK,   TYPE_INT    },
  { "TCP.FLAG.FIN",     TCP,      FIELD_TCP_FLAG_FIN,   TYPE_INT    },
  { "TCP.FLAG.PSH",     TCP,      FIELD_TCP_FLAG_PSH,   TYPE_INT    },
  { "TCP.FLAG.RST",     TCP,      FIELD_TCP_FLAG_RST,   TYPE_INT    },
  { "TCP.FLAG.SYN",     TCP,      FIELD_TCP_FLAG_SYN,   TYPE_INT    },
  { "TCP.FLAG.URG",     TCP,      FIELD_TCP_FLAG_URG,   TYPE_INT    },
  { "TCP.SRCPORT",      TCP,      FIELD_TCP_SRCPORT,    TYPE_INT    },
  { "TCP.SEQ",          TCP,      FIELD_TCP_SEQ,        TYPE_INT    },
  { "TCP.URGPTR",       TCP,      FIELD_TCP_URGPTR,     TYPE_INT    },
  { "TCP.WINDOW",       TCP,      FIELD_TCP_WINDOW,     TYPE_INT    },
  /* UDP */
  { "UDP.CHKSUM",       UDP,      FIELD_UDP_CHKSUM,     TYPE_INT    },
  { "UDP.DSTPORT",      UDP,      FIELD_UDP_DSTPORT,    TYPE_INT    },
  { "UDP.LEN",          UDP,      FIELD_UDP_LEN,        TYPE_INT    },
  { "UDP.SRCPORT",      UDP,      FIELD_UDP_SRCPORT,    TYPE_INT    },
};

/**
 * print table for human consumption of all support protocols, types, fields supported
 */
void pkt_data_dump(void)
{
  char proto[32];
  unsigned i, j;
  enum pkt p = PKT_NONE;
  const struct pktfieldmap *pfm;
  const struct pkttype_match *pm;
  for (i = 0; i < sizeof PktFieldMap / sizeof PktFieldMap[0]; i++) {
    pfm = PktFieldMap + i;
    if (p != pfm->pkt_id) {
      p = pfm->pkt_id;
      strlcpy(proto, pfm->str, sizeof proto);
      proto[strcspn(proto, ".")] = '\0';
      printf("%s\n", proto);
      printf("  Messages:\n");
      for (j = 0; j < sizeof PktTypes / sizeof PktTypes[0]; j++) {
        pm = PktTypes + j;
        if (pm->pkt == pfm->pkt_id)
          printf("    %s\n", pm->str);
      }
      printf("  Fields:\n");
    }
    printf("    %-16s %-5s\n", pfm->str, datatype_to_str(pfm->type));
  }
}


const char * pkt_to_str(enum pkt p)
{
  return PktProps[p].name;
}

/**
 * test whether packet-specific type matches pkttype
 * @note assume that p->pkt is the correct type
 * @return 1 on success, 0 on failure
 */
int pkttype_match(enum pkttype t, const struct packet *p)
{
  switch (t) {
  case PKT_NONE:
    return 0;
  default:
    fprintf(stderr, "pkttype_match() don't know pkttype %d!\n", t);
    abort();
  case PKT_ARP_REQ:
    return ARP_OP_REQ == p->data.arp->ar_op;
  case PKT_ARP_RESP:
    return ARP_OP_RESP == p->data.arp->ar_op;
  case PKT_ETH:
    return 1;
  case PKT_IP:
    return 1;
  case PKT_IP6:
    return 1;
  case PKT_UDP:
    return 1;
  case PKT_ICMP_PING:
    return ICMP_ECHO == p->data.icmp->type;
  case PKT_ICMP_PONG:
    return ICMP_ECHOREPLY == p->data.icmp->type;
  case PKT_ICMP:
    return 1;
  case PKT_BOOTP:
    return 1;
  case PKT_BOOTP_REQ:
    return BOOTP_TYPE_REQ == p->data.bootp->type;
  case PKT_BOOTP_RESP:
    return BOOTP_TYPE_RESP == p->data.bootp->type;
  case PKT_TCP:
    return 1;
  case PKT_TCP_SYN:
    return 1 == p->data.tcp->syn;
  case PKT_TCP_RST:
    return 1 == p->data.tcp->rst;
  case PKT_TCP_FIN:
    return 1 == p->data.tcp->fin;
  case PKT_DNS:
    return 1;
  case PKT_DNS_REQ:
    return 0 == p->data.dns->qr;
  case PKT_DNS_RESP:
    return 1 == p->data.dns->qr;
  /* NBNS */
  case PKT_NBNS:
    return 1;
  case PKT_NBNS_REQ:
    return 0 == p->data.nbns->q;
  case PKT_NBNS_RESP:
    return 1 == p->data.nbns->q;
  case PKT_NBNS_QUERY:
    return NBNS_OP_QUERY == p->data.nbns->op;
  case PKT_NBNS_REGISTER:
    return NBNS_OP_REGISTER == p->data.nbns->op;
  case PKT_NBNS_RELEASE:
    return NBNS_OP_RELEASE == p->data.nbns->op;
  case PKT_NBNS_WACK:
    return NBNS_OP_WACK == p->data.nbns->op;
  case PKT_NBNS_REFRESH:
    return NBNS_OP_REFRESH == p->data.nbns->op;
  /* LLC */
  case PKT_LLC:
    return 1;
  case PKT_LLC_SNAP:
    return LLC_DSAP_SNAP == p->data.llc->dsap;
  /* CDP */
  case PKT_CDP:
    return 1;
  /* STP */
  case PKT_STP:
    return 1;
  /* DTP */
  case PKT_DTP:
    return 1;
  /* NBDGM */
  case PKT_NBDGM:
    return 1;
  /* SNMP */
  case PKT_SNMP:
    return 1;
  }
}

/* TODO: i forget which order the key/match gets passed in as... */
static int pkttype_str_cmp(const void *va, const void *vb)
{
  const struct pkttype_match *a = va;
  const char *b = vb;
  return strcmp(a->str, b);
}

const struct pkttype_match * pkttype_match_str(const char *str)
{
  const struct pkttype_match *m;
  m = bsearch(str, PktTypes, sizeof PktTypes / sizeof PktTypes[0],
    sizeof PktTypes[0], pkttype_str_cmp);
  return m;
}

const char * pkttype_to_str(enum pkttype p)
{
  return PktTypeStr[p];
}

const struct pktfieldmap * pktfield_get_map(enum pktfield p)
{
  return PktFieldMap + p;
}

static int pktfieldmap_cmp(const void *va, const void *vb)
{
  const struct pktfieldmap *a = va, *b = vb;
  return strcmp(a->str, b->str);
}

const struct pktfieldmap * pktfield_get_map_str(const char *s)
{
  struct pktfieldmap key, *find;
  strlcpy(key.str, s, sizeof key.str);
  find = bsearch(&key, PktFieldMap, sizeof PktFieldMap / sizeof PktFieldMap[0],
                  sizeof PktFieldMap[0], pktfieldmap_cmp);
#ifdef DEBUG
  printf("pktfield_get_map_str(%s) -> %p (%u)\n", s, (void *)find, (unsigned)(find - PktFieldMap));
#endif
  return find;
}


/* O(1) translation of pktfield id to name */
static const char *PktFieldStr[FIELD_COUNT];

/**
 * initialize prot data structures that need it
 */
void prot_init(void)
{
  unsigned i;
  PktFieldStr[0] = "None";
  PktFieldStr[FIELD_COUNT - 1] = "ARGH?! COUNT";
  for (i = 0; i < sizeof PktFieldMap / sizeof PktFieldMap[0]; i++)
    PktFieldStr[PktFieldMap[i].id] = PktFieldMap[i].str;
}

const char * pktfield_to_str(enum pktfield f)
{
  return PktFieldStr[f];
}

/**
 * @return number of bytes consumed by self + any sub-parsing
 * @note assume ethernet
 */
unsigned parse_linux_sll(struct cap *c)
{
  unsigned used = ETH_HLEN;
  struct ethhdr *e;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[ETH].len_min)
    return 0;
  e = c->pkt[c->pkt_cnt].data.eth = (struct ethhdr *)c->raw;
  c->prots[ETH] = c->pkt_cnt++;
  c->used += ETH_HLEN;
  switch (e->h_proto) {
  case ETH_P_ARP:
    used += parse_arp(c);
    break;
  default:
    fprintf(stderr, "parse_eth() unknown h_proto: %hu\n", e->h_proto);
    break;
  }
  return used;
}

/**
 * dump a single packet of any type to stdout in semi-human-readable format
 */
void packet_dump(const struct packet *p)
{
  char ipbuf[64]; /* ip4 and ip6 */
  switch (p->pkt) {
  case LOGIC:
  {
    const struct pktlogic *l = &p->data.logic;
    const struct tm *tm = &l->tm;
    printf("LOGIC   ");
    printf(" frame=%-9lu", l->frame);
    printf(" date=%04d-%02d-%02dT%02d:%02d:%02d.%03ld",
      1900 + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday,
      tm->tm_hour, tm->tm_min, tm->tm_sec,
      p->data.logic.header->ts.tv_usec / 1000);
    printf(" len=%u", l->len);
    printf(" used=%u", l->used);
    printf("\n");
  }
    break;
  case ETH:
  {
    const struct ethhdr *e = p->data.eth;
    printf("ETH     ");
    printf(" h_dest=%02x:%02x:%02x:%02x:%02x:%02x",
      e->h_dest[0], e->h_dest[1], e->h_dest[2],
      e->h_dest[3], e->h_dest[4], e->h_dest[5]);
    printf(" h_source=%02x:%02x:%02x:%02x:%02x:%02x",
      e->h_source[0], e->h_source[1], e->h_source[2],
      e->h_source[3], e->h_source[4], e->h_source[5]);
    printf(" h_proto=0x%04x(%s)\n", p->data.eth->h_proto, eth_prot_by_id(p->data.eth->h_proto));
  }
    break;
  case ARP:
  {
    const struct arphead *a = p->data.arp;
    printf("ARP     ");
    printf(" ar_hrd=0x%04x", a->ar_hrd);
    printf(" ar_pro=0x%04x", a->ar_pro);
    printf(" ar_hln=0x%04x", a->ar_hln);
    printf(" ar_pln=%-2u", a->ar_pln);
    printf(" ar_op=0x%04x", a->ar_op);
    printf(" ar_sha=%02x:%02x:%02x:%02x:%02x:%02x",
      a->ar_sha[0], a->ar_sha[1], a->ar_sha[2],
      a->ar_sha[3], a->ar_sha[4], a->ar_sha[5]);
    sprintf(ipbuf, "%u.%u.%u.%u",
      a->ar_sip[0], a->ar_sip[1], a->ar_sip[2], a->ar_sip[3]);
    printf(" ar_sip=%-15s", ipbuf);
    printf(" ar_tha=%02x:%02x:%02x:%02x:%02x:%02x",
      a->ar_tha[0], a->ar_tha[1], a->ar_tha[2],
      a->ar_tha[3], a->ar_tha[4], a->ar_tha[5]);
    sprintf(ipbuf, "%u.%u.%u.%u",
      a->ar_tip[0], a->ar_tip[1], a->ar_tip[2], a->ar_tip[3]);
    printf(" ar_tip=%-15s", ipbuf);
    printf("\n");
  }
    break;
  case IP:
  {
    struct ip ip;
    const struct iphdr *i = p->data.ip;
    printf("IP      ");
    printf(" ver=%u", i->version);
    printf(" hlen=%-3u", i->ihl << 2);
    printf(" tos=0x%02X", i->tos);
    printf(" totlen=%-5u", i->tot_len);
    printf(" id=0x%04X", i->id);
    printf(" dontfrag=%1u", !!(i->frag_off & IP_DONTFRAG));
    printf(" morefrag=%1u", !!(i->frag_off & IP_MOREFRAG));
    sprintf(ipbuf, "%u.%u.%u.%u",
      (i->saddr & 0xFF), (i->saddr >> 8) & 0xFF,
      (i->saddr >> 16) & 0xFF, i->saddr >> 24);
    printf(" src=%-15s", ipbuf);
    sprintf(ipbuf, "%u.%u.%u.%u",
      (i->daddr & 0xFF), (i->daddr >> 8) & 0xFF,
      (i->daddr >> 16) & 0xFF, i->daddr >> 24);
    printf(" dst=%-15s", ipbuf);
    printf(" proto=0x%02x", i->protocol);
    printf("\n");
  }
    break;
  case UDP:
  {
    const struct udphdr *u = p->data.udp;
    printf("UDP     ");
    printf(" srcport=%-5u", u->source);
    printf(" dstport=%-5u", u->dest);
    printf(" len=%-5u", u->len);
    printf(" chksum=0x%04x\n", u->check);
  }
    break;
  case ICMP:
  {
    const struct icmphdr *i = p->data.icmp;
    printf("ICMP    ");
    printf(" type=0x%02x", i->type);
    printf(" code=0x%02x", i->code);
    printf(" chksum=0x%04x", i->checksum);
    printf(" payloadlen=%-5u", p->len - 8);
    switch (i->code) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
      printf(" id=0x%04x", i->un.echo.id);
      printf(" seq=0x%04x", i->un.echo.sequence);
      break;
    case ICMP_DEST_UNREACH:
      break;
    case ICMP_SOURCE_QUENCH:
      break;
    case ICMP_REDIRECT:
      break;
    case ICMP_TIME_EXCEEDED:
      break;
    case ICMP_PARAMETERPROB:
      break;
    case ICMP_TIMESTAMP:
      break;
    case ICMP_TIMESTAMPREPLY:
      break;
    case ICMP_INFO_REQUEST:
      break;
    case ICMP_INFO_REPLY:
      break;
    case ICMP_ADDRESS:
      break;
    case ICMP_ADDRESSREPLY:
      break;
    }
    printf(" payload=");
    /* always dump contents of ICMP(?) */
    chars_dump((unsigned char *)i + 8, p->len - 8);
    printf("\n");
  }
    break;
  case TCP:
  {
    const struct tcphdr *t = p->data.tcp;
    printf("TCP     ");
    printf(" srcport=%-5u", t->source);
    printf(" dstport=%-5u", t->dest);
    printf(" seq=%-9lu", (unsigned long)t->seq);
    printf(" ackseq=%-9lu", (unsigned long)t->ack_seq);
    printf(" window=%-5u", t->window);
    printf(" chksum=0x%04x", t->check);
    printf(" urg_ptr=%-5u", t->urg_ptr);
    {
      char flagbuf[64] = "";
      if (t->res1) sprintf(flagbuf, "res1=%04x,", t->res1);
      if (t->doff) sprintf(flagbuf + strlen(flagbuf), "doff=%04x,", t->doff);
      if (t->fin) strlcat(flagbuf, "fin,", sizeof flagbuf);
      if (t->syn) strlcat(flagbuf, "syn,", sizeof flagbuf);
      if (t->rst) strlcat(flagbuf, "rst,", sizeof flagbuf);
      if (t->psh) strlcat(flagbuf, "psh,", sizeof flagbuf);
      if (t->ack) strlcat(flagbuf, "ack,", sizeof flagbuf);
      if (t->urg) strlcat(flagbuf, "urg,", sizeof flagbuf);
      if (t->ece) strlcat(flagbuf, "ece,", sizeof flagbuf);
      if (t->cwr) strlcat(flagbuf, "cwr,", sizeof flagbuf);
      if (strlen(flagbuf))
        flagbuf[strlen(flagbuf) - 1] = '\0';
      printf("flags=(%s)\n", flagbuf);
    }
  }
    break;
  case BOOTP:
  {
    const struct bootphdr *b = p->data.bootp;
    printf("BOOTP   ");
    printf(" type=0x%02x", b->type);
    printf(" hw_type=0x%02x", b->hw_type);
    printf(" hw_len=%-3u", b->hw_len);
    printf(" hops=%-3u", b->hops);
    printf(" trans_id=0x%08x", b->trans_id);
    printf(" secs=%-5u", b->secs);
    printf(" flags=0x%04x", b->flags);
    sprintf(ipbuf, "%u.%u.%u.%u",
      b->client_ip[0], b->client_ip[1], b->client_ip[2], b->client_ip[3]);
    printf(" client_ip=%-15s", ipbuf);
    sprintf(ipbuf, "%u.%u.%u.%u",
      b->your_ip[0], b->your_ip[1], b->your_ip[2], b->your_ip[3]);
    printf(" your_ip=%-15s", ipbuf);
    sprintf(ipbuf, "%u.%u.%u.%u",
      b->next_ip[0], b->next_ip[1], b->next_ip[2], b->next_ip[3]);
    printf(" next_ip=%-15s", ipbuf);
    sprintf(ipbuf, "%u.%u.%u.%u",
      b->relay_ip[0], b->relay_ip[1], b->relay_ip[2], b->relay_ip[3]);
    printf(" relay_ip=%-15s", ipbuf);
    printf(" magic_cookie=0x%08x", b->magic_cookie);
    printf(" server_host=");
    chars_dump((unsigned char *)b->server_host, strlen(b->server_host));
    printf(" boot_file=");
    chars_dump((unsigned char *)b->boot_file, strlen(b->boot_file));
    printf("\n");
  }
    break;
  case DNS:
  {
    char rcodebuf[32];
    const struct dnshdr *d = p->data.dns;
    printf("DNS     ");
    printf(" id=0x%04x", d->id);
    printf(" qr=%1u", d->qr);
    printf(" opcode=0x%x", d->opcode);
    printf(" aa=%1u", d->aa);
    printf(" tc=%1u", d->tc);
    printf(" rd=%1u", d->rd);
    printf(" ra=%1u", d->ra);
    printf(" z=%1u%s", d->z, (d->z ? "(!)" : "   ")); /* reserved field MUST be zero */
    sprintf(rcodebuf, "(%.*s)", (int)sizeof rcodebuf, DNS_Rcode[d->rcode]);
    printf(" rcode=%1u%-16s", d->rcode, rcodebuf);
    printf(" q_cnt=%-3u", d->q_cnt);
    printf(" ans_rr_cnt=%-3u", d->ans_rr_cnt);
    printf(" auth_rr_cnt=%-3u", d->auth_rr_cnt);
    printf(" add_rr_cnt=%-3u", d->add_rr_cnt);
    printf("\n");
  }
    break;
  case NBNS:
  {
    const struct nbnshdr *n = p->data.nbns;
    printf("NBNS    ");
    printf(" q=%1u", (int)n->q);
    printf(" trunc=%1u", (int)n->trunc);
    printf(" recurs=%1u", (int)n->recurs);
    printf(" bcast=%1u", (int)n->bcast);
    printf(" op=0x%x(%s)", (int)n->op, NBNS_Ops[n->op & NBNS_OP_MASK]);
    printf(" name=%-16s", n->name);
    printf("\n");
  }
    break;
  case LLC:
  {
    const struct llchdr *l = p->data.llc;
    printf("LLC     ");
    printf(" dsap=0x%02x", l->dsap);
    printf(" ssap=0x%02x", l->ssap);
    printf(" ctrl=%2x", l->ctrl);
    printf(" frame=%1u", l->frame);
    if (LLC_DSAP_SNAP == l->dsap) {
      printf(" org=0x%02x%02x%02x",
        l->data.snap.org[0], l->data.snap.org[1], l->data.snap.org[2]);
      printf(" pid=0x%04x", (int)l->data.snap.pid);
    }
    printf("\n");
  }
    break;
  case CDP:
  {
    const struct cdphdr *c = &p->data.cdp;
    unsigned i;
    printf("CDP     ");
    printf(" ver=%1u", c->ver);
    printf(" ttl=%-3u", c->ttl);
    printf(" chksum=0x%04x", c->chksum);
    printf(" nodecnt=%u", c->nodecnt);
    for (i = 1; i < c->nodecnt; i++) {
      const struct cdpnode *n;
      n = c->node + i;
      switch (n->type) {
      case CDP_TYPE_DEVID:
        printf(" devid=%s", n->data.dev.id);
        break;
      case CDP_TYPE_PORTID:
        printf(" portid=%s", n->data.port.iface);
        break;
      case CDP_TYPE_SOFTWARE:
        printf(" software=%s", n->data.soft.ver);
        break;
      case CDP_TYPE_PLATFORM:
        printf(" platform=%s", n->data.plat.form);
        break;
      default:
#       ifdef DEBUG
          printf(" node[%u].type=%u", i, n->type);
#       endif
        break;
      }
    }
    printf("\n");
  }
    break;
  case NBDGM:
  {
    const struct nbdgmhdr *n = &p->data.nbdgm;
    const struct nbdgmfixed *h = n->head;
    printf("NBDGM   ");
    printf(" type=0x%x", (int)h->type);
    printf(" more_frag=%1u", (int)h->more_frag);
    printf(" first_frag=%1u", (int)h->first_frag);
    printf(" node_type=%1u", (int)h->node_type);
    printf(" id=0x%04x", (int)h->id);
    sprintf(ipbuf, "%u.%u.%u.%u",
      (int)h->ip[0], (int)h->ip[1],
      (int)h->ip[2], (int)h->ip[3]);
    printf(" ip=%-15s", ipbuf);
    printf(" srcport=%-5u", (int)h->srcport);
    printf(" len=%-5u", (int)h->len);
    printf(" offset=%-5u", (int)h->off);
    printf(" srcname=%-20s", n->srcname);
    printf(" dstname=%-20s", n->dstname);
    printf("\n");
  }
    break;
  case SNMP:
  {
    const struct snmphdr *s = &p->data.snmp;
    printf("SNMP    ");
    printf("...");
    printf("\n");
  }
    break;
  case IP6:
  {
    const struct ip6hdr *i = p->data.ip6;
    printf("IPv6    ");
    printf(" ver=%1u", i->ver);
    printf(" trafclass=0x%04x", i->trafclass);
    printf(" flow=0x%05x", i->flow);
    printf(" paylen=%-5u", i->paylen);
    printf(" nexthdr=%-3u", i->nexthdr);
    printf(" hoplim=%-3u", i->hoplim);
    printf(" src=%-20s", ip_addr_to_str(ipbuf, sizeof ipbuf, 6, i->src));
    printf(" dst=%-20s", ip_addr_to_str(ipbuf, sizeof ipbuf, 6, i->dst));
    printf("\n");
  }
    break;
  case PPPOE:
  {
    const struct pppoehdr *o = p->data.pppoe;
    printf("PPPoE   ");
    printf(" ver=%-2u", o->ver);
    printf(" type=0x%x", o->type);
    printf(" sessid=0x%04x", o->sessid);
    printf(" len=%-5u", o->len);
    printf("\n");
  }
    break;
  default:
    printf("can't handle pkt %u!\n", p->pkt);
    break;
  }
}

void cap_dump(const struct cap *c)
{
  unsigned i;
  for (i = 0; i < c->pkt_cnt; i++) {
    printf("  [%u] ", i);
    packet_dump(c->pkt + i);
  }
  if (Verbose > 0 && c->used < c->len) {
    printf("  [-] Trailing ");
    chars_dump(c->raw + c->used, (size_t)(c->len - c->used));
    printf("\n");
  }
}

/**
 * @return number of bytes consumed by self + any sub-parsing
 * @note assume ethernet
 */
unsigned parse_eth(struct cap *c)
{
  unsigned used = ETH_HLEN;
  struct packet *p;
  struct ethhdr *e;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[ETH].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = ETH;
  p->type = PKT_ETH;
  p->len = ETH_HLEN;
  e = c->pkt[c->pkt_cnt].data.eth = (struct ethhdr *)c->raw;
  c->prots[ETH] = c->pkt_cnt++;
  c->used += ETH_HLEN;
  /* fixups */
  e->h_proto = ntohs(e->h_proto);
  if (e->h_proto > ETH_MTU) {
    switch (e->h_proto) {
    case ETH_P_ARP:
      used += parse_arp(c);
      break;
    case ETH_P_IP:
      used += parse_ip(c);
      break;
    case ETH_P_IPV6:
      used += parse_ip6(c);
      break;
    case ETH_P_RARP:
      printf("parse_eth() h_proto=0x%04X RARP...\n", e->h_proto);
      break;
    case ETH_P_LOOP:
      printf("parse_eth() h_proto=0x%04X LOOP...\n", e->h_proto);
      break;
    case ETH_P_PPP_DISC:
    case ETH_P_PPP_SES:
      used += parse_pppoe(c);
      break;
    default:
#ifdef DEBUG
      fprintf(stderr, "parse_eth() unknown h_proto: %04X\n", e->h_proto);
#endif
      break;
    }
  } else {
    /* <=1500 are 802.3 and can be identified by reserved MAC addresses */
    static const struct eth802_3_mac {
      unsigned char mac[6];
      unsigned len;
      enum pkt proto;
    } Eth802_3[] = {
      /* NOTE: MUST be in ascending alpha order by mac! */
      /*mac                         len proto */
      { "\x01\x00\x0C\xCC\xCC\xCC", 6,  LLC   }, /* CDP, must parse LLC first */
      { "\x01\x80\xC2\x00\x00",     5,  STP   },
    };
    unsigned i;
    for (i = 0; i < sizeof Eth802_3 / sizeof Eth802_3[0]; i++)
      if (Eth802_3[i].mac[0] == e->h_dest[0] && 0 == memcmp(Eth802_3[i].mac, e->h_dest, Eth802_3[i].len)) {
        used += (Parse_Func[Eth802_3[i].proto])(c);
        break;
      }
  }
  return used;
}

/**
 * @return number of bytes consumed by self + any sub-parsing
 * @note assume ethernet
 */
unsigned parse_arp(struct cap *c)
{
  struct packet *p;
  struct arphead *a;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[ARP].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = ARP;
  p->len = ARP_LEN;
  a = c->pkt[c->pkt_cnt].data.arp = (struct arphead *)(c->raw + c->used);
  c->prots[ARP] = c->pkt_cnt++;
  /* basic validation for assumptions */
  if (a->ar_hln != 6 || a->ar_pln != 4) {
    fprintf(stderr, "ar_hln(%u) != 6 || ar_pln(%u) != 4\n",
      (unsigned int)a->ar_hln, (unsigned int)a->ar_pln);
    return 0;
  }
  /* fixups */
  a->ar_hrd = ntohs(a->ar_hrd);
  a->ar_pro = ntohs(a->ar_pro);
  a->ar_op = ntohs(a->ar_op);
  switch (a->ar_op) {
  case ARP_OP_REQ:
    p->type = PKT_ARP_REQ;
    break;
  case ARP_OP_RESP:
    p->type = PKT_ARP_RESP;
    break;
  default:
    p->type = PKT_NONE;
    break;
  }
  /* we're ok with this... */
  c->used += ARP_LEN;
  return ARP_LEN;
}

/**
 *
 */
unsigned parse_ip(struct cap *c)
{
  struct packet *p;
  struct iphdr *i;
  unsigned used;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[ARP].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = IP;
  i = c->pkt[c->pkt_cnt].data.ip = (struct iphdr *)(c->raw + c->used);
  c->prots[IP] = c->pkt_cnt++;
  /* IP-specific stuff */
  used = i->ihl << 2; /* calculate len * 4 */
  c->used += used;
  p->len = used;
  /* fixups */
  i->tot_len = ntohs(i->tot_len);
  i->id = ntohs(i->id);
  i->frag_off = ntohs(i->frag_off);
  i->check = ntohs(i->check);
#if 0
  printf("offset:%2u, ver:%u, hlen:%2u, tos:0x%02X, totlen:%5u, id:0x%04X, protocol: %2u\n",
    c->used, i->version, used, i->tos, i->tot_len, i->id, i->protocol);
#endif
  switch (i->protocol) {
  case IPPROTO_ICMP:
#if 0
    printf("parse_ip() ICMP\n");
#endif
    used += parse_icmp(c);
    break;
  case IPPROTO_IGMP:
#ifdef DEBUG
    printf("parse_ip() IGMP\n");
#endif
    break;
  case IPPROTO_TCP:
    used += parse_tcp(c);
    break;
  case IPPROTO_UDP:
    used += parse_udp(c);
    break;
  case IPPROTO_GRE:
#ifdef DEBUG
#if 0
    printf("parse_ip() GRE\n");
#endif
#endif
    break;
  default:
    printf("parse_ip() unexpected IP protocol: %u\n", (unsigned)i->protocol);
    break;
  }
  return used;
}

/**
 *
 */
unsigned parse_udp(struct cap *c)
{
  struct packet *p;
  struct udphdr *u;
  unsigned used = 8;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[UDP].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = UDP;
  u = c->pkt[c->pkt_cnt].data.udp = (struct udphdr *)(c->raw + c->used);
  c->prots[UDP] = c->pkt_cnt++;
  /* IP-specific stuff */
  c->used += used;
  p->len = used;
  /* fixups */
  u->source = ntohs(u->source);
  u->dest = ntohs(u->dest);
  u->len = ntohs(u->len);
  u->check = ntohs(u->check);
  switch ((u->source << 8) | u->dest) {
  case ((PORT_UDP_BOOTPS << 8) | PORT_UDP_BOOTPC):
  case ((PORT_UDP_BOOTPC << 8) | PORT_UDP_BOOTPS):
    used += parse_bootp(c);
    break;
  default:
    if (PORT_UDP_DNS == u->source || PORT_UDP_DNS == u->dest)
      used += parse_dns(c);
    else if (PORT_UDP_NBNS == u->source || PORT_UDP_NBNS == u->dest)
      used += parse_nbns(c);
    else if (PORT_UDP_NBDGM == u->source || PORT_UDP_NBDGM == u->dest)
      used += parse_nbdgm(c);
    else if (PORT_UDP_SNMP == u->source || PORT_UDP_SNMP == u->dest)
      used += parse_snmp(c);
    break;
  }
  return used;
}

/**
 *
 */
unsigned parse_icmp(struct cap *c)
{
  struct packet *p;
  struct icmphdr *i;
  unsigned used = c->len - c->used; /* nothing can be embedded in ICMP; gobble the whole thing */
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[ICMP].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = ICMP;
  i = c->pkt[c->pkt_cnt].data.icmp = (struct icmphdr *)(c->raw + c->used);
  c->prots[ICMP] = c->pkt_cnt++;
  /* IP-specific stuff */
  c->used += used;
  p->len = used;
  /* fixups */
  i->checksum = ntohs(i->checksum);
  switch (i->code) {
  case ICMP_ECHOREPLY:
  case ICMP_ECHO:
    i->un.echo.id = ntohs(i->un.echo.id);
    i->un.echo.sequence = ntohs(i->un.echo.sequence);
    break;
  case ICMP_DEST_UNREACH:
    break;
  case ICMP_SOURCE_QUENCH:
    break;
  case ICMP_REDIRECT:
    break;
  case ICMP_TIME_EXCEEDED:
    break;
  case ICMP_PARAMETERPROB:
    break;
  case ICMP_TIMESTAMP:
    break;
  case ICMP_TIMESTAMPREPLY:
    break;
  case ICMP_INFO_REQUEST:
    break;
  case ICMP_INFO_REPLY:
    break;
  case ICMP_ADDRESS:
    break;
  case ICMP_ADDRESSREPLY:
    break;
  }
  return used;
}

/**
 *
 */
unsigned parse_bootp(struct cap *c)
{
  struct packet *p;
  struct bootphdr *b;
  unsigned used = c->len - c->used;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[BOOTP].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = BOOTP;
  b = c->pkt[c->pkt_cnt].data.bootp = (struct bootphdr *)(c->raw + c->used);
  c->prots[BOOTP] = c->pkt_cnt++;
  /* IP-specific stuff */
  c->used += used;
  p->len = used;
  /* fixups */
  b->trans_id = ntohl(b->trans_id);
  b->secs = ntohs(b->secs);
#if 0 /* specifically do not do flags, right?! */
  b->flags = ntohs(b->flags);
#endif
  b->magic_cookie = ntohl(b->magic_cookie);
  return used;
}

/**
 *
 */
unsigned parse_tcp(struct cap *c)
{
  struct packet *p;
  struct tcphdr *t;
  unsigned used = 20;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[TCP].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = TCP;
  t = c->pkt[c->pkt_cnt].data.tcp = (struct tcphdr *)(c->raw + c->used);
  c->prots[TCP] = c->pkt_cnt++;
  /* TCP-specific stuff */
  c->used += used;
  p->len = used;
  /* fixups */
  t->source = ntohs(t->source);
  t->dest = ntohs(t->dest);
  t->seq = ntohl(t->seq);
  t->ack_seq = ntohl(t->ack_seq);
  t->window = ntohs(t->window);
  t->check = ntohs(t->check);
  t->urg_ptr = ntohs(t->urg_ptr);
  return used;
}

/**
 * just parse DNS header, more later, maybe
 */
unsigned parse_dns(struct cap *c)
{
  struct packet *p;
  struct dnshdr *d;
  unsigned used = (unsigned)sizeof *d;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[DNS].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = DNS;
  d = c->pkt[c->pkt_cnt].data.dns = (struct dnshdr *)(c->raw + c->used);
  c->prots[DNS] = c->pkt_cnt++;
  c->used += used;
  p->len = used;
  /* fixups */
  d->q_cnt = ntohs(d->q_cnt);
  d->ans_rr_cnt = ntohs(d->ans_rr_cnt);
  d->auth_rr_cnt = ntohs(d->auth_rr_cnt);
  d->add_rr_cnt = ntohs(d->add_rr_cnt);
  return used;
}

/**
 * parse NetBIOS-Namserver protocol header. maybe more later.
 */
unsigned parse_nbns(struct cap *c)
{
  struct packet *p;
  struct nbnshdr *n;
  unsigned used = (unsigned)sizeof *n; /* we should really swallow all, but we're not parsing. so we'll just dump it */
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[NBNS].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = NBNS;
  n = c->pkt[c->pkt_cnt].data.nbns = (struct nbnshdr *)(c->raw + c->used);
  c->prots[NBNS] = c->pkt_cnt++;
  /* parse variable-width */
  do {
    unsigned char *d, /* current data */
                  *s; /* search */
    size_t len,
           left, /* bytes left in message */
           copy; /* how many bytes to copy into fixed-width field */
    n->name[0] = '\0';
    d = (unsigned char *)n + used;
    left = c->len - c->used - used;
    /* copy variable-length srcname */
    s = memchr(d, '\0', left);
    if (NULL == s)
      break;
    len = (size_t)(s - d) + 1;
    copy = len;
    if (copy >= sizeof n->name)
      copy = sizeof n->name - 1;
    strlcpy(n->name, (char *)d, copy);
    msft_decode(n->name, n->name, copy);
    used += len;
  } while (0);
  /* fixups */
  n->trans_id = ntohs(n->trans_id);
  n->ans_rr_cnt = ntohs(n->ans_rr_cnt);
  n->auth_rr_cnt = ntohs(n->auth_rr_cnt);
  n->add_rr_cnt = ntohs(n->add_rr_cnt);
  /* accounting */
  c->used += used;
  p->len = used;
  return used;
}

/**
 * link level c(?)
 */
unsigned parse_llc(struct cap *c)
{
  struct packet *p;
  struct llchdr *l;
  unsigned used = 3;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[LLC].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = LLC;
  l = c->pkt[c->pkt_cnt].data.llc = (struct llchdr *)(c->raw + c->used);
  c->prots[LLC] = c->pkt_cnt++;
  /* sub-types and fixups */
  if (LLC_DSAP_SNAP == l->dsap) {
    used += 5;
    l->data.snap.pid = ntohs(l->data.snap.pid);
  }
  c->used += used;
  p->len = used;
  /* sub-protocols */
  switch (l->dsap) {
  case LLC_DSAP_SNAP:
    switch (l->data.snap.pid) {
    case LLC_PID_CDP:
      used += parse_cdp(c);
      break;
    case LLC_PID_DTP:
      /* TODO: add DTP support, for now i just don't care */
      break;
    default:
      printf("parse_llc() DSAP=SNAP, unhandled Pid: 0x%04x\n", l->data.snap.pid);
      break;
    }
    break;
  default:
    printf("parse_llc() unhandled DSAP: 0x%04x\n", l->dsap);
    break;
  }
  return used;
}

/**
 *
 */
unsigned parse_cdp(struct cap *c)
{
  struct packet *p;
  struct cdphdr *cdp;
  unsigned char *d; /* data */
  unsigned used = 0, left = c->len - c->used; /* swallow it all */
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[CDP].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = CDP;
  cdp = &c->pkt[c->pkt_cnt].data.cdp;
  c->prots[CDP] = c->pkt_cnt++;
  d = c->raw + c->used;
  cdp->ver = d[used++];
  cdp->ttl = d[used++];
  cdp->chksum = (d[used] << 8) | d[used + 1];
    used += 2;
  cdp->nodecnt = 0;
  while (
    cdp->nodecnt < sizeof cdp->node / sizeof cdp->node[0] - 1
    && used + 4 <= left
  ) {
    struct cdpnode *n;
    uint16_t type, len, copy;
    type = *(uint16_t *)(d + used);
    len = *(uint16_t *)(d + used + 2);
    used += 4;
    type = ntohs(type);
    len = ntohs(len);
    if (len < 4 || used + len - 4 > left || type >= CDP_TYPE_CNT) {
      printf("parse_cdp() len=%u, left=%u, used + len=%u, type=%u\n", len, left, used + len, type);
      break; /* invalid value */
    }
    n = cdp->node + ++cdp->nodecnt; /* skip 0 */
    n->type = type;
    n->len = len;
    cdp->node_idx[type] = cdp->nodecnt;
    copy = len - 4;
    switch (type) {
    /* deal with supported types, skip others */
    case CDP_TYPE_DEVID:
      if (copy > sizeof n->data.dev.id - 1)
        copy = sizeof n->data.dev.id - 1;
      n->data.dev.len = copy;
      strlcpy(n->data.dev.id, (char *)(d + used), copy + 1);
      break;
    case CDP_TYPE_PORTID:
      if (copy > sizeof n->data.port.iface - 1)
        copy = sizeof n->data.port.iface - 1;
      n->data.port.len = copy;
      strlcpy(n->data.port.iface, (char *)(d + used), copy + 1);
      break;
    case CDP_TYPE_CAPAB:
      if (copy >= 4)
        memcpy(&n->data.capab, d + used - 2, 6);
      break;
    case CDP_TYPE_SOFTWARE:
      if (copy > sizeof n->data.soft.ver - 1)
        copy = sizeof n->data.soft.ver - 1;
      n->data.soft.len = copy;
      strlcpy(n->data.soft.ver, (char *)(d + used), copy + 1);
      break;
    case CDP_TYPE_PLATFORM:
      if (copy > sizeof n->data.soft.ver - 1)
        copy = sizeof n->data.soft.ver - 1;
      n->data.soft.len = copy;
      strlcpy(n->data.soft.ver, (char *)(d + used), copy + 1);
      break;
    default:
      printf("parse_cdp() unknown cdp type 0x%02x\n",
        (int)type);
    case CDP_TYPE_ADDRS:
    case CDP_TYPE_PROTHELLO:
    case CDP_TYPE_VTPMANDOM:
    case CDP_TYPE_NATVLAN:
    case CDP_TYPE_DUPLEX:
    case CDP_TYPE_TRUST:
    case CDP_TYPE_UNTRUSTCOS:
    case CDP_TYPE_MNGMTADDR:
      /* unsupported but recognized */
      break;
    }
    used += len - 4;
  }
  c->used += used;
  return used;
}

/**
 *
 */
unsigned parse_stp(struct cap *c)
{
  return 0;
}

/**
 *
 */
unsigned parse_dtp(struct cap *c)
{
  return 0;
}

/**
 *
 */
unsigned parse_nbdgm(struct cap *c)
{
  struct packet *p;
  struct nbdgmhdr *n;
  struct nbdgmfixed *h; /* fixed-width header */
  unsigned used = (unsigned)sizeof *h;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[NBDGM].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = NBDGM;
  n = &c->pkt[c->pkt_cnt].data.nbdgm;
  c->prots[NBDGM] = c->pkt_cnt++;
  /* fixed-width */
  h = n->head = (struct nbdgmfixed *)(c->raw + c->used);
  /* fixup fixed-width */
  h->id = ntohs(h->id);
  h->srcport = ntohs(h->srcport);
  h->len = ntohs(h->len);
  h->off = ntohs(h->off);
  /* parse variable-width */
  do {
    unsigned char *d, /* current data */
                  *s; /* search */
    size_t len,
           left, /* bytes left in message */
           copy; /* how many bytes to copy into fixed-width field */
    n->srcname[0] = '\0';
    n->dstname[0] = '\0';
    d = (unsigned char *)h + used;
    left = c->len - c->used - used;
    /* copy variable-length srcname */
    s = memchr(d, '\0', left);
    if (NULL == s)
      break;
    len = (size_t)(s - d) + 1;
    copy = len;
    if (copy >= sizeof n->srcname)
      copy = sizeof n->srcname - 1;
    strlcpy(n->srcname, (char *)d, copy);
    msft_decode(n->srcname, n->srcname, copy);
    left -= len;
    used += len;
    d += len;
    /* copy variable-length dstname */
    s = memchr(d, '\0', left);
    if (NULL == s)
      break;
    len = (size_t)(s - d) + 1;
    copy = len;
    if (copy >= sizeof n->dstname)
      copy = sizeof n->dstname - 1;
    strlcpy(n->dstname, (char *)d, copy);
    msft_decode(n->dstname, n->dstname, copy);
    used += len;
  } while (0);
  /* update cap */
  c->used += used;
  /* sub-protocols */
  /* ... */
  return used;
}

/**
 * token implementation of SNMP, simply so we can detect its presence
 */
unsigned parse_snmp(struct cap *c)
{
  struct packet *p;
  struct snmphdr *s;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[SNMP].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = SNMP;
  s = &c->pkt[c->pkt_cnt].data.snmp;
  c->prots[SNMP] = c->pkt_cnt++;
  /* fixed-width */
  return 0;
}

/**
 *
 */
unsigned parse_ip6(struct cap *c)
{
  struct packet *p;
  struct ip6hdr *i;
  unsigned used = (unsigned)sizeof *i;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[IP6].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = IP6;
  i = c->pkt[c->pkt_cnt].data.ip6 = (struct ip6hdr *)(c->raw + c->used);
  c->prots[IP6] = c->pkt_cnt++;
  /* fixed-width */
  c->used += used;
  return used;
}

/**
 *
 */
unsigned parse_pppoe(struct cap *c)
{
  struct packet *p;
  struct pppoehdr *o;
  unsigned used = (unsigned)sizeof *o;
  if (MAX_PKT == c->pkt_cnt)
    return 0;
  if (c->len - c->used < PktProps[PPPOE].len_min)
    return 0;
  p = c->pkt + c->pkt_cnt;
  p->pkt = PPPOE;
  o = c->pkt[c->pkt_cnt].data.pppoe = (struct pppoehdr *)(c->raw + c->used);
  c->prots[PPPOE] = c->pkt_cnt++;
  /* fixed-width */
  c->used += used;
  return used;
}


