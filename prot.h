/* $Id$ */
/* ex: set ts=2 et: */

#ifndef PROT_H
#define PROT_H

#include <arpa/inet.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include "type.h"


#ifndef MAX_CAP
# define MAX_CAP      4096  /* bytes per cap */
#endif
#define MAX_PKT       8     /* level of nesting we will handle */

/* ensure endianness defined */
#if !defined(__LITTLE_ENDIAN_BITFIELD) && !defined(__BIG_ENDIAN_BITFIELD)
# error "no __LITTLE_ENDIAN_BITFIELD nor __BIG_ENDIAN_BITFIELD #defined!"
#endif

/* all supported protocols */
enum pkt {
  UNKNOWN = 0,
  LOGIC, /* "logical" frame, not really a protocol, but hey */
  LINUX_SLL,
  ETH,
  ARP,
  IP,
  ICMP,
  UDP,
  TCP,
  DNS,
  BOOTP,
  NBNS,
  LLC,
  CDP,
  STP,
  DTP,
  NBDGM,
  SNMP,
  IP6,
  IGMP,
  PPPOE,
  PROT_MAX
};

/**
 *
 */
static const struct pkt_prop {
  const char name[20];
  unsigned len_min,
           len_max;
} PktProps[PROT_MAX] = {
  /* NOTE: order tied to `enum pkt` */
  /*name        min   max  */
  { "Unknown"  ,0    ,0     },
  { "LOGIC"    ,0    ,0     },
  { "Linux SLL",16   ,16    },
  { "ETH"      ,14   ,14    },
  { "ARP"      ,28   ,28    }, /* FIXME: Ethernet assumed */
  { "IP"       ,20   ,60    },
  { "ICMP"     ,8    ,8     },
  { "UDP"      ,8    ,8     },
  { "TCP"      ,20   ,60    },
  { "DNS"      ,12   ,0     },
  { "BOOTP"    ,206  ,0     },
  { "NBNS"     ,12   ,12    },
  { "LLC"      ,8    ,8     },
  { "CDP"      ,8    ,1024  }, /* FIXME: max is a guess! */
  { "STP"      ,35   ,35    },
  { "DTP"      ,1    ,1024  }, /* FIXME: max is a guess */
  { "NBDGM"    ,14   ,160   }, /* FIXME: max is a guess */
  { "SNMP"     ,0    ,0     }, /* FIXME: partial implementation */
  { "IP6"      ,40   ,0     },
  { "PPPoE"    ,48   ,0     },
};

const char * pkt_to_str(enum pkt);


/* the types of packets that are matchable */
enum pkttype {
  PKT_NONE = 0,
  PKT_ARP_REQ,
  PKT_ARP_RESP,
  PKT_ETH,
  PKT_IP,
  PKT_UDP,
  PKT_ICMP,
  PKT_ICMP_PING,
  PKT_ICMP_PONG,
  PKT_BOOTP,
  PKT_BOOTP_REQ,
  PKT_BOOTP_RESP,
  PKT_TCP,
  PKT_TCP_SYN,
  PKT_TCP_RST,
  PKT_TCP_FIN,
  PKT_DNS,
  PKT_DNS_REQ,
  PKT_DNS_RESP,
  PKT_NBNS,
  PKT_NBNS_REQ,
  PKT_NBNS_RESP,
  PKT_NBNS_QUERY,
  PKT_NBNS_REGISTER,
  PKT_NBNS_RELEASE,
  PKT_NBNS_WACK,
  PKT_NBNS_REFRESH,
  PKT_LLC,
  PKT_LLC_SNAP,
  PKT_CDP,
  PKT_STP,
  PKT_DTP,
  PKT_NBDGM,
  PKT_SNMP,
  PKT_IP6,
  PKT_PPPOE,
  PKT_PPPOE_DISC,
  PKT_PPPOE_SESS,
  PKT_COUNT
};

/* O(1) translation of name -> str */
static const char *PktTypeStr[] = {
  "(None)",
  "ARP:REQ",
  "ARP:RESP",
  "ETH",
  "IP",
  "UDP",
  "ICMP",
  "ICMP:PING",
  "ICMP:PONG",
  "BOOTP",
  "BOOTP:REQ",
  "BOOTP:RESP",
  "TCP",
  "TCP:SYN",
  "TCP:RST",
  "TCP:FIN",
  "DNS",
  "DNS:REQ",
  "DNS:RESP",
  "NBNS",
  "NBNS:REQ",
  "NBNS:RESP",
  "NBNS:QUERY",
  "NBNS:REGISTER",
  "NBNS:RELEASE",
  "NBNS:WACK",
  "NBNS:REFRESH",
  "LLC",
  "LLC:SNAP",
  "CDP",
  "STP",
  "DTP",
  "NBDGM",
  "SNMP",
  "IP6",
  "PPPoE",
  "PPPoE:DISC",
  "PPPoE:SESS",
  "WHOOPS?!"
};

/* packet type record */
struct pkttype_match {
  char str[32];
  enum pkt pkt;
  enum pkttype type;
};

const struct pkttype_match * pkttype_match_str(const char *str);
const char * pkttype_to_str(enum pkttype);

/* SLL */
#define SLL_ADDRLEN       8

/* Ethernet */
/* types defined in /usr/include/linux/if_ether.h */

/* ref: http://www.iana.org/assignments/ethernet-numbers */
#define ETH_MTU           1500
#define ETH_IS_LEN(n)     ((n) <= ETH_MTU)
#define ETH_IS_TYPE(n)    ((n) > ETH_MTU) 

const char * eth_prot_by_id(uint16_t);

/* ARP - Address Resolution Protocol */
#define ARP_LEN           28 /* NOTE: assume Ethernet */
#define ARP_OP_REQ        0x0001
#define ARP_OP_RESP       0x0002

/* IP - Internet Protocol v4 */
#define IP_DONTFRAG       0x4000
#define IP_MOREFRAG       0x2000
#define IP_OFFMASK        0x1FFF

//#include "ip_prot.h" /* ip protocol table */

/* UDP - User Datagram Protocol */

/* BOOTP */
#define BOOTP_TYPE_REQ    0x1
#define BOOTP_TYPE_RESP   0x2
#define BOOTP_FLAG_BCAST  0x8000

/* TCP */


/* UDP and TCP ports */

#define PORT_UDP_DNS      53
#define PORT_UDP_BOOTPS   67
#define PORT_UDP_BOOTPC   68
#define PORT_UDP_NBNS     137
#define PORT_UDP_NBDGM    138
#define PORT_UDP_SNMP     161

/* DNS */

#define DNS_QUERY_STD     0x1
#define DNS_QUERY_INV     0x2
#define DNS_QUERY_STAT    0x4

#define DNS_RCODE_OK      0x0
#define DNS_RCODE_ERRFMT  0x1
#define DNS_RCODE_ERRSVR  0x2
#define DNS_RCODE_NONAME  0x3
#define DNS_RCODE_NOTYPE  0x4
#define DNS_RCODE_REFUSE  0x5

static const char *DNS_Rcode[] = {
  /* 0x0 */ "OK",
  /* 0x1 */ "FormatErr",
  /* 0x2 */ "ServFail",
  /* 0x3 */ "NXDomain",
  /* 0x4 */ "NotImp",
  /* 0x5 */ "Refused",
  /* 0x6 */ "YXDomain",
  /* 0x7 */ "YXRRSet",
  /* 0x8 */ "NXRRSet",
  /* 0x9 */ "NotAuth",
  /* 0xA */ "NotZone",
  /* 0xB */ "11?!",
  /* 0xC */ "12?!",
  /* 0xD */ "13?!",
  /* 0xE */ "14?!",
  /* 0xF */ "15?!",
};


/* NBNS */
#define NBNS_OP_QUERY       0x0
#define NBNS_OP_REGISTER    0x5
#define NBNS_OP_RELEASE     0x6
#define NBNS_OP_WACK        0x7
#define NBNS_OP_REFRESH     0x8
#define NBNS_OP_REFRESHALT  0x9
#define NBNS_OP_MHREG       0xF
#define NBNS_OP_MASK        0xF /* mask */

static const char *NBNS_Ops[] = {
  "query",
  "1?!",
  "2?!",
  "3?!",
  "4?!",
  "register",
  "release",
  "wack",
  "refresh",
  "refresh(alt)",
  "10?!",
  "11?!",
  "12?!",
  "13?!",
  "14?!",
  "multi-homed reg"
};

/* LLC */
#define LLC_DSAP_SNAP     0xAA
#define LLC_PID_CDP       0x2000
#define LLC_PID_DTP       0x2004

/* CDP */
#define CDP_TYPE_DEVID      0x01
#define CDP_TYPE_ADDRS      0x02
#define CDP_TYPE_PORTID     0x03
#define CDP_TYPE_CAPAB      0x04
#define CDP_TYPE_SOFTWARE   0x05
#define CDP_TYPE_PLATFORM   0x06
#define CDP_TYPE_PROTHELLO  0x08
#define CDP_TYPE_VTPMANDOM  0x09
#define CDP_TYPE_NATVLAN    0x0A
#define CDP_TYPE_DUPLEX     0x0B
#define CDP_TYPE_TRUST      0x12
#define CDP_TYPE_UNTRUSTCOS 0x13
#define CDP_TYPE_MNGMTADDR  0x16
#define CDP_TYPE_CNT        0x17 /* must always be one higher than last */

/* STP */

/* DTP */

/* NBDGM */

/* SNMP */

/* IPv6 */


/* a single chunk of protocol data contained in a msg */
struct packet {
  enum pkt pkt;
  enum pkttype type;
  unsigned len;
  union {
    /* logical frame, first frame of each cap */
    struct pktlogic {
      struct pcap_pkthdr *header;
      struct tm tm;
      unsigned long frame;
      unsigned len, /* total length */
               used; /* total used by all */ 
    } logic;
    /* Anything unidentified hanging off the end */
    struct pkt_unknown {
      unsigned char *data;
      unsigned len;
    } unknown;
    /* A DLT_LINUX_SLL fake link-layer header */
    struct linux_sll_hdr {
      uint16_t pkttype,
               hatype,
               halen;
      uint8_t addr[SLL_ADDRLEN];
      uint16_t protocol;
    } __attribute__((packed)) *linux_sll;
    /* Ethernet II */
    /* IEEE 802.3 Ethernet */
    struct ethhdr *eth;
    /* ARP - Address Resolution Protocol */
    struct arphead {
      /* assume ethernet */
      unsigned short ar_hrd,          /* format of hardware addr */
                     ar_pro;          /* format of protocol addr */
      unsigned char ar_hln,           /* length of hardware addr */
                    ar_pln;           /* length of protocol addr */
      unsigned short ar_op;           /* operation */
      unsigned char ar_sha[ETH_ALEN], /* sender hardware addr */
                    ar_sip[4],        /* sender ip */
                    ar_tha[ETH_ALEN], /* target hardware addr */
                    ar_tip[4];        /* target ip */
    } __attribute__((packed)) *arp;
    /* IP */
    struct iphdr *ip;
    /* UDP */
    struct udphdr *udp;
    /* ICMP */
    struct icmphdr *icmp;
    /* BOOTP */
    struct bootphdr {
      unsigned char type,
                    hw_type,
                    hw_len,
                    hops;
      uint32_t trans_id;
      uint16_t secs,
               flags;
      unsigned char client_ip[4],
                    your_ip[4],
                    next_ip[4],
                    relay_ip[4];
      unsigned char client_mac[6];
      char server_host[64];
      char boot_file[128];
      uint32_t magic_cookie;
      /* we then have sets of options until we hit 0xFF */
      struct bootp_opt {
        int todo;
      } __attribute__((packed)) opts;
    } *bootp;
    /* TCP */
    struct tcphdr *tcp;
    /* DNS - custom */
    struct dnshdr {
      /* ref: RFC1035 */
      uint16_t id;
#if defined(__BIG_ENDIAN_BITFIELD)
      uint16_t ra:1,      /* Recursion Available */
               z:3,       /* reZerved */
               rcode:4,   /* Response CODE */
               qr:1,      /* query(0) or response(1) */
               opcode:4,  /* type of query */
               aa:1,      /* Authorative Answer */
               tc:1,      /* TrunCation */
               rd:1;      /* Recursion Denied */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
      uint16_t
              rd:1,      /* Recursion Denied */
              tc:1,      /* TrunCation */
              aa:1,      /* Authorative Answer */
              opcode:4,  /* type of query */
              qr:1,      /* query(0) or response(1) */
              ra:1,      /* Recursion Available */
              z:3,       /* reZerved */
              rcode:4;   /* Response CODE */
#endif
      uint16_t q_cnt, ans_rr_cnt, auth_rr_cnt, add_rr_cnt;
    } __attribute__((packed)) *dns;
    /* NBNS */
    struct nbnshdr {
      uint16_t trans_id;
#if defined(__BIG_ENDIAN_BITFIELD)
      uint16_t dunno2:4, bcast:1, dunno1:3, recurs:1, trunc:1, op:4, q:1;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
      uint16_t q:1, op:4, trunc:1, recurs:1, dunno1:3, bcast:1, dunno2:4;
#endif
      uint16_t q_cnt, ans_rr_cnt, auth_rr_cnt, add_rr_cnt;
      /* variable width */
      char name[64];
    } __attribute__((packed)) *nbns;
    /* LLC */
    struct llchdr {
      unsigned char dsap; /* destination service access point */
      unsigned char ssap; /* source service access point */
      unsigned char ctrl:6, frame:2;
      union {
        struct {
          unsigned char org[3];
          uint16_t pid;
        } __attribute__((packed)) snap;
      } data;
    } __attribute__((packed)) *llc;
    /* CDP - Cisco Discovery Protocol */
    struct cdphdr {
      unsigned char ver;
      unsigned char ttl;
      uint16_t chksum;
      /* fixed-width ends; following nodes may come in any order and are variable-width */
      unsigned nodecnt;
      struct cdpnode {
        uint16_t type;
        uint16_t len;
        union {
          /* TODO: combine similar text fields into a single struct */
          struct {
            uint16_t len;
            char id[32];
          } dev;
          struct {
            uint16_t len;
            char iface[32];
          } port;
          struct {
            uint16_t len;
            /* TODO: fix endianness?! */
            uint32_t unused:25,
                     repeater:1,
                     igmp:1,
                     host:1,
                     swtch:1,
                     src_rt_bridge:1,
                     trans_bridge:1,
                     router:1;
          } capab;
          struct {
            uint16_t len;
            char ver[256];
          } soft;
          struct {
            uint16_t len;
            char form[64];
          } plat;
        } data;
      } node[16];
      unsigned node_idx[CDP_TYPE_CNT]; /*  */
    } __attribute__((packed)) cdp;
    /* NBDGM - NetBIOS Datagram */
    struct nbdgmhdr {
      /* fixed-width */
      struct nbdgmfixed {
        unsigned char type;
        unsigned char unused_flag:4,
                      node_type:2,
                      first_frag:1,
                      more_frag:1;
        uint16_t id;
        unsigned char ip[4];
        uint16_t srcport,
                len,
                off;
      } __attribute__((packed)) *head;
      /* variable width */
      char srcname[64];
      char dstname[64];
    } nbdgm;
    /* SNMP */
    struct snmphdr {
      int unused;
    } snmp;
    /* IPv6 */
    struct ip6hdr {
#if defined(__BIG_ENDIAN_BITFIELD)
      uint32_t      ver:4,
                    trafclass:8,
                    flow:20;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
      uint32_t      flow:20,
                    trafclass:8,
                    ver:4;
#endif
      uint16_t      paylen;
      uint8_t       nexthdr;
      uint8_t       hoplim;
      unsigned char src[16],
                    dst[16];
    } __attribute__((packed)) *ip6;
    /* IGMP */
    struct igmphdr {
      int unused;
    } igmp;
    /* PPPoE */
    struct pppoehdr {
#if defined(__BIG_ENDIAN_BITFIELD)
      uint32_t ver:4,
               type:4,
               code:8,
               sessid:16;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
      uint32_t sessid:16,
               code:8,
               type:4,
               ver:4;
#endif
      uint16_t len;
    } *pppoe;
  } data;
};


/* a raw captured chunk of data, hot off the network */
struct cap {
  unsigned len,     /* total data in byte[] */
           used,    /* total bytes from byte[] parsed into pkt[] */
           pkt_cnt, /* number of pkt[] entries already used */
           prots[PROT_MAX]; /* set of indexes to entries by protocol */
  struct packet pkt[MAX_PKT];
  unsigned char *raw;
};

unsigned parse_linux_sll(struct cap *);
unsigned parse_eth(struct cap *);
unsigned parse_arp(struct cap *);
unsigned parse_ip(struct cap *);
unsigned parse_udp(struct cap *);
unsigned parse_bootp(struct cap *);
unsigned parse_icmp(struct cap *);
unsigned parse_tcp(struct cap *);
unsigned parse_dns(struct cap *);
unsigned parse_nbns(struct cap *);
unsigned parse_llc(struct cap *);
unsigned parse_cdp(struct cap *);
unsigned parse_stp(struct cap *);
unsigned parse_nbdgm(struct cap *);
unsigned parse_snmp(struct cap *);
unsigned parse_ip6(struct cap *);
unsigned parse_pppoe(struct cap *);


/* NOTE: MUST be synced with `enum pkt` */
static unsigned (*Parse_Func[])(struct cap *) = {
  NULL, /* UNKNOWN */
  NULL, /* LOGIC */
  parse_linux_sll,
  parse_eth,
  parse_arp,
  parse_ip,
  parse_icmp,
  parse_udp,
  parse_tcp,
  parse_dns,
  parse_bootp,
  parse_nbns,
  parse_llc,
  parse_cdp,
  parse_stp,
  parse_nbdgm,
  parse_snmp,
  parse_ip6,
  parse_pppoe
};

int pkttype_match(enum pkttype, const struct packet *);

/* all fields against which rules may be tested */
enum pktfield {
  FIELD_NONE = 0,
  /* ETH */
  FIELD_ETH_SRC,
  FIELD_ETH_DST,
  FIELD_ETH_TYPE,
  FIELD_ETH_LEN,
  FIELD_ETH_TRAILER,
  FIELD_ETH_VENDID,
  /* ARP */
  FIELD_ARP_SRC_MAC,
  FIELD_ARP_SRC_IP,
  FIELD_ARP_DST_MAC,
  FIELD_ARP_DST_IP,
  /* IP */
  FIELD_IP_DST,
  FIELD_IP_ID,
  FIELD_IP_DONTFRAG,
  FIELD_IP_MOREFRAG,
  FIELD_IP_LEN,
  FIELD_IP_PROT,
  FIELD_IP_SRC,
  FIELD_IP_TOTALLEN,
  FIELD_IP_TTL,
  /* UDP */
  FIELD_UDP_SRCPORT,
  FIELD_UDP_DSTPORT,
  FIELD_UDP_LEN,
  FIELD_UDP_CHKSUM,
  /* ICMP */
  FIELD_ICMP_TYPE,
  FIELD_ICMP_CODE,
  FIELD_ICMP_PAYLOAD,
  FIELD_ICMP_LEN,
  /* BOOTP */
  FIELD_BOOTP_TYPE,
  FIELD_BOOTP_CLIENT_IP,
  FIELD_BOOTP_CLIENT_MAC,
  /* TCP */
  FIELD_TCP_SRCPORT,
  FIELD_TCP_DSTPORT,
  FIELD_TCP_SEQ,
  FIELD_TCP_ACKSEQ,
  FIELD_TCP_WINDOW,
  FIELD_TCP_CHKSUM,
  FIELD_TCP_URGPTR,
  FIELD_TCP_FLAG_URG,
  FIELD_TCP_FLAG_ACK,
  FIELD_TCP_FLAG_PSH,
  FIELD_TCP_FLAG_RST,
  FIELD_TCP_FLAG_SYN,
  FIELD_TCP_FLAG_FIN,
  /* TODO: add TCP OPTIONS */
  /* DNS */
  FIELD_DNS_Q,
  FIELD_DNS_QFLAGS,
  FIELD_DNS_AUTH,
  FIELD_DNS_TRUNC,
  FIELD_DNS_REC_AVAIL,
  FIELD_DNS_RCODE,
  FIELD_DNS_CNT_Q,
  FIELD_DNS_CNT_ANS_RR,
  FIELD_DNS_CNT_AUTH_RR,
  FIELD_DNS_CNT_ADD_RR,
  /* NBNS */
  FIELD_NBNS_Q,
  FIELD_NBNS_OP,
  FIELD_NBNS_TRUNC,
  FIELD_NBNS_RECURSE,
  FIELD_NBNS_BCAST,
  FIELD_NBNS_CNT_Q,
  FIELD_NBNS_CNT_ANS_RR,
  FIELD_NBNS_CNT_AUTH_RR,
  FIELD_NBNS_CNT_ADD_RR,
  /* LLC */
  FIELD_LLC_DSAP,
  FIELD_LLC_SSAP,
  FIELD_LLC_ORG,
  FIELD_LLC_PID,
  /* CDP */
  FIELD_CDP_VER,
  FIELD_CDP_TTL,
  FIELD_CDP_CHKSUM,
  FIELD_CDP_DEVID,
  FIELD_CDP_PORT,
  FIELD_CDP_SOFTWARE,
  FIELD_CDP_PLATFORM,
  /* STP */
  /* DTP */
  /* NBDGM */
  FIELD_NBDGM_TYPE,
  FIELD_NBDGM_NODETYPE,
  FIELD_NBDGM_FIRSTFRAG,
  FIELD_NBDGM_MOREFRAG,
  FIELD_NBDGM_SRCPORT,
  FIELD_NBDGM_LEN,
  FIELD_NBDGM_SRCNAME,
  FIELD_NBDGM_DSTNAME,
  /* SNMP */
  FIELD_SNMP_,
  /* IP6 */
  FIELD_IP6_VER,
  FIELD_IP6_TRAFCLASS,
  FIELD_IP6_FLOWLBL,
  FIELD_IP6_PAYLEN,
  FIELD_IP6_NEXTHDR,
  FIELD_IP6_HOPLIM,
  FIELD_IP6_SRC,
  FIELD_IP6_DST,
  /* IGMP */
  /* total count */
  FIELD_COUNT
};

/* records about what fields belong to which packets */
struct pktfieldmap {
  char str[32]; /* human-enterable string */
  enum pkt pkt_id; /* what type of packet does this match? */
  enum pktfield id; /* what field within the packet? */
  enum datatype type; /* what is the datatype of this field? */
};

void prot_init(void);

const struct pktfieldmap * pktfield_get_map(enum pktfield);
const struct pktfieldmap * pktfield_get_map_str(const char *);

void packet_dump(const struct packet *);
void cap_dump(const struct cap *);

void pkt_data_dump(void);

#endif

