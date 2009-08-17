/* $Id$ */
/* ex: set ts=2 et: */
/*
 * LANassert - a canary in the cave of the local network
 * Copyright (C) 2006  Ryan "pizza" Flynn
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include "prot.h"
#include "rule.h"
#include "util.h"

#define IFACE_MAX       4
#define IFACE_BUFLEN    64

/* exported */
int Verbose = 0;
const char *ConfigFile = NULL;

/* static */
static int Shutdown = 0;
static int Reload_Config = 0;
static unsigned Iface_Cnt = 0;
static char Dev_Str[IFACE_MAX][IFACE_BUFLEN];
static struct ip Ip_Listening[IFACE_MAX];
static bpf_u_int32 Dev_Mask[IFACE_MAX];
static bpf_u_int32 Dev_Net[IFACE_MAX];
static pcap_t *Pcap[IFACE_MAX] = { NULL };
static int Datalink[IFACE_MAX];
static unsigned long Frame = 0;

extern void parse_config(void);

static void sig_handle(int sig)
{
#ifdef SIGHUP
  signal(SIGHUP, sig_handle);
#endif
  signal(SIGINT, sig_handle);
  signal(SIGTERM, sig_handle);
  switch (sig) {
#ifdef SIGHUP
  case SIGHUP:
    Reload_Config = 1;
    break;
#endif
  case SIGINT:
  case SIGTERM:
    Shutdown = 1;
    printf("received signal %d, shutting down...\n", sig);
    break;
  default:
    printf("received signal %d, doing nothing.\n", sig);
    break;
  }
}

static void print_help(void)
{
        /*01234567890123456789012345678901234567890123456789012345678901234567890123456789*/
  printf("Usage: %s [options]\n", "LANassert");
  printf("Options:\n");
  printf(" -i [?|iface] ...... network interface to use (REQUIRED). '?' lists all.\n");
  printf(" -c [configfile] ... specify configfile (REQUIRED)\n");
  printf(" -v ................ increase output verbosity\n");
  printf(" -h [opt]........... help, with optional argument\n");
  printf("    ref ............ protocol support reference\n");
  printf("Example: sudo LANassert -i eth0 -c myconfig\n");
  printf("\n");
}

static char DatalinkStr[256][16];
void init_data(void)
{
  unsigned i;
  /* install signal handlers */
#ifdef SIGHUP
  signal(SIGHUP, sig_handle);
#endif
  signal(SIGINT, sig_handle);
  signal(SIGTERM, sig_handle);
  /* initialize protocol structures */
  prot_init();
  /* fill in datalink names */
  for (i = 0; i < (unsigned)(sizeof DatalinkStr / sizeof DatalinkStr[0]); i++)
    sprintf(DatalinkStr[i], "#%u", i);
  strlcpy(DatalinkStr[DLT_IEEE802],   "IEEE802",    sizeof DatalinkStr[0]);
  strlcpy(DatalinkStr[DLT_EN10MB],    "ETH10MB",    sizeof DatalinkStr[0]);
  strlcpy(DatalinkStr[DLT_LINUX_SLL], "LinuxSLL",   sizeof DatalinkStr[0]);
}

static void iface_list(void)
{
  pcap_if_t *alldevs, *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  if (-1 == pcap_findalldevs(&alldevs, errbuf)) {
    fprintf(stderr, "Error building iface list: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  printf("Interfaces:\n");
  printf("%-8s %s\n", "Name", "Description");
  printf("-------------------------------------------------------\n");
  for (dev = alldevs; dev; dev = dev->next)
    printf("%-8s %s\n",
      dev->name, (dev->description ? dev->description : "(None)"));
  pcap_freealldevs(alldevs);
}

static void iface_find_or_exit(const char *wildcard)
{
  pcap_if_t *alldevs, *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  if (-1 == pcap_findalldevs(&alldevs, errbuf)) {
    fprintf(stderr, "Error building iface list: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  printf("Search for interface '%s'... ", wildcard);
  for (dev = alldevs; dev; dev = dev->next) {
    if ('\0' != wildcard[0] && NULL == strstr(dev->name, wildcard) && (NULL == dev->description || NULL == strstr(dev->description, wildcard)))
      continue;
    printf("OK.\n");
    strlcpy(Dev_Str[Iface_Cnt++], dev->name, sizeof Dev_Str);
    if (IFACE_MAX == Iface_Cnt) {
      printf("Interface limit reached.\n");
      break;
    }
  }
  if (0 == Iface_Cnt) {
    iface_list();
    fprintf(stderr, "No interfaces matched '%s', quitting.\n", wildcard);
    exit(EXIT_FAILURE);
  }
  pcap_freealldevs(alldevs);
}

void parse_cmdline(int argc, char *argv[])
{
  int opt;
  const char opts[] = "i:c:vh::";
  while (-1 != (opt = getopt(argc, argv, opts))) {
    switch (opt) {
    case 'c':
      ConfigFile = optarg;
      break;
    case 'i':
      if ('?' == optarg[0]) {
        iface_list();
        exit(EXIT_SUCCESS);
      }
      iface_find_or_exit(optarg);
      break;
    case 'v':
      Verbose++;
      break;
    case 'h':
      print_help();
      if (NULL != argv[optind]) { /* optional help */
        switch (argv[optind][0]) {
        case 'r': /* reference */
          printf("Protocol Reference\n");
          printf("-------------------------------------------------------\n");
          pkt_data_dump();
          break;
        default:
          break;
        }
      }
      printf("\n");
      exit(EXIT_SUCCESS);
      break;
    default:
      fprintf(stderr, "%s option '%c'. See -h\n",
        (NULL == strchr(opts, optopt) ? "Unrecognized" : "Invalid use of"), optopt);
      exit(EXIT_SUCCESS);
    }
  }
  /* check for required params */
  if (0 == Iface_Cnt) {
    fprintf(stderr, "No interface specified. Use one of the following with -i\n");
    iface_list();
    exit(EXIT_FAILURE);
  }
  if (NULL == ConfigFile) {
    fprintf(stderr, "Config file required. See -h\n");
    exit(EXIT_FAILURE);
  }
}


/**
 * data has been received; initialize/fill in the rest of the cap structure,
 * figure out how to parse it, hand off to parsers, then hand parsed data to apply_rules()
 */
static void process_packet(unsigned iface, struct cap *c)
{
  unsigned (*parse)(struct cap *) = NULL;
  struct tm *tm;
  /* initialize cap */
  c->used = 0;
  c->pkt_cnt = 1; /* we're using first entry for logical */
  memset(c->prots, 0, sizeof c->prots);
  /* fill in logical frame */
  c->pkt[0].pkt = LOGIC;
  c->pkt[0].type = PKT_NONE;
  c->pkt[0].len = 0;
  c->pkt[0].data.logic.frame = Frame++;
  c->pkt[0].data.logic.len = c->len;
  c->pkt[0].data.logic.used = 0;
  tm = localtime(&c->pkt[0].data.logic.header->ts.tv_sec);
  memcpy(&c->pkt[0].data.logic.tm, tm, sizeof *tm);
  /* figure out packet's entry parse routine */
  switch (Datalink[iface]) {
  case DLT_EN10MB: /* ethernet */
    parse = parse_eth;
    break;
  case DLT_LINUX_SLL:
    parse = parse_linux_sll;
    break;
  default:
    fprintf(stderr, "process_packet(%u, %p) don't know datalink %d\n",
      iface, (void *)c, Datalink[iface]);
    break;
  }
  {
    unsigned bytes;
    bytes = parse(c);
    if (0 == bytes) {
      printf("packet not parsed...\n");
      return;
    } else if (bytes < c->len) { /* handle unknown trailing data */
      c->pkt[c->pkt_cnt].pkt = UNKNOWN;
      c->pkt[c->pkt_cnt].len = c->len - bytes;
      c->pkt[c->pkt_cnt].data.unknown.data = c->raw + c->used;
      c->pkt[c->pkt_cnt].data.unknown.len = c->len - bytes;
      c->pkt_cnt++;
      return;
    }
    c->pkt[0].data.logic.used = c->used;
    rules_apply(c);
  }
}

static void net_loop(void)
{
  unsigned i;
  struct cap cap;
  signed fds[IFACE_MAX];
  signed fdmax = INT_MIN;
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  memset(&cap, 0, sizeof cap);
  for (i = 0; i < Iface_Cnt; i++) {
    fds[i] = pcap_get_selectable_fd(Pcap[i]);
    if (fds[i] > fdmax)
      fdmax = fds[i];
  }
  while (!Shutdown) {
    fd_set rd;
    signed sel;
    FD_ZERO(&rd);
    if (Reload_Config) { /* reload config file if requested */
      Reload_Config = 0;
      printf("Clearing existing rules...\n");
      rules_clear();
      printf("Reloading config file...\n");
      parse_config();
    }
    for (i = 0; i < Iface_Cnt; i++)
      FD_SET(fds[i], &rd);
    sel = select(fdmax + 1, &rd, NULL, NULL, NULL);
    if (-1 == sel) {
      perror("select");
      continue;
    } else if (0 == sel) {
      continue;
    }
    for (i = 0; i < Iface_Cnt; i++) {
      if (!FD_ISSET(fds[i], &rd))
        continue;
      if (1 != pcap_next_ex(Pcap[i], &cap.pkt[0].data.logic.header, (const unsigned char **)&cap.raw))
        continue;
      cap.len = (unsigned)cap.pkt[0].data.logic.header->len;
      process_packet(i, &cap);
    }
  }
}

void iface_loop(void)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  unsigned i;
  const signed promisc = 1;
  do {
    /* set up each iface */
    for (i = 0; i < Iface_Cnt; i++) {
      printf("Opening %s... ", Dev_Str[i]);
      Pcap[i] = pcap_open_live(Dev_Str[i], MAX_CAP, promisc, 0, errbuf);
      if (NULL == Pcap[i]) {
        printf("%s\n", errbuf);
        continue;
      }
      printf("OK.\n");
      Datalink[i] = pcap_datalink(Pcap[i]);
    }
    net_loop();
    printf("interfaces down...\n");
  } while (!Shutdown);
  printf("iface loop done.\n");
}


