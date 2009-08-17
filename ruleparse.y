/* $Id$ */
/* ex: set ts=2 et: */

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "prot.h"
#include "rule.h"
#include "util.h"

extern char *yytext;
unsigned long Lineno = 1; /* exported */

static void parse_vars_reset(void);

static char PktType[64] = "",
            PktField[64] = "",
            VarName[64];
static struct match_node CurMatch, *CurLink = NULL; /*  */
static struct rule CurRule;
static enum logic Logic = LOGIC_OR;
static enum pkt Protocol = UNKNOWN;
static int Rule_Disabled = 0;


#ifndef DEBUG
#define YYDEBUG 0
#endif

%}

%union {
  char token[256];
  unsigned pkt; /*  */
  long i;
}

/* tokens */
%token T_INTEGER
%token T_STR
%token T_IDENTIFIER
%token T_VARNAME
/* cmp */
%token T_EQL
%token T_NEQ
%token T_NOT
%token T_IS
%token T_IN
%token T_GT
%token T_LT
%token T_GTE
%token T_LTE
/* logic */
%token T_AND
%token T_OR
/* keywords */
%token T_RULE
%token T_EXPLAIN
%token T_DISABLE
%token T_ALARM
%token T_MATCH
%token T_ASSERT
%token T_EMAIL
%token T_AUDIO
%token T_VAR
%token T_BREAK
/* protocol */
%token T_ETH
%token T_ARP
%token T_BOOTP
%token T_ICMP
%token T_IP
%token T_UDP
%token T_DNS
%token T_TCP
%token T_NBNS
%token T_SMB
%token T_LLC
%token T_CDP
%token T_STP
%token T_DTP
%token T_NBDGM
%token T_SNMP
%token T_IP6
%token T_IGMP
%token T_WTF
/* types */
%token T_MACADDR
%token T_IPADDR
%token T_PORT
%token T_COUNT

%%

config:
  statement
  | config statement
  ;

statement:
  alias
  | rule
  ;

alias:
  T_VAR T_VARNAME {
    strlcpy(VarName, yylval.token, sizeof VarName);
    match_node_init(&CurMatch);
  } data ';' {
#ifdef DEBUG
    printf("ALIAS VARNAME=%s DATA=", VarName);
    rule_data_dump(&CurMatch.data, CurMatch.datatype);
    printf("\n");
#endif
    (void)alias_add(VarName, CurMatch.datatype, &CurMatch.data);
  }
  ;

rule:
  T_RULE T_STR {
    (void)strlunescape($2.token, $2.token + 1, strlen($2.token) - 1);
#ifdef DEBUG
      printf("RULE \"%s\"\n", $2.token);
#endif
      strlcpy(CurRule.name, $2.token, sizeof CurRule.name);
    }
    disabled_section
    match_section
    assert_section
    break_section
    ';' {
#ifdef DEBUG
    printf("RULE\n");
#endif
    if (Rule_Disabled) {
      printf("RULE SKIP \"%s\"\n", CurRule.name);
      Rule_Disabled = 0;
    } else {
      printf("RULE ADD \"%s\"\n", CurRule.name);
      rule_add(&CurRule);
    }
  }
  ;

disabled_section:
  T_DISABLE {
    Rule_Disabled = 1;
  }
  | /* or not... */
  ;

break_section: /* this causes reduce/reduce conflict */
  T_BREAK {
    CurRule.fail_break = 1;
  }
  | /* or not... */
  ;

logic_op:
  T_AND {
    Logic = LOGIC_AND;
#ifdef DEBUG
    printf("LOGIC -> AND\n");
#endif
  }
  | T_OR {
    Logic = LOGIC_OR;
#ifdef DEBUG
    printf("LOGIC -> OR\n");
#endif
  }
  ;

match_section:
  T_MATCH protocol_msgtype { /* optional arguments */
#ifdef DEBUG
    printf("==== match_section\n");
#endif
    CurLink = match_add(CurLink, &CurMatch, Logic);
    while (CurLink && CurLink->parent)
      CurLink = CurLink->parent;
#ifdef DEBUG
    match_node_dump_deep(CurLink, 0);
#endif
    CurRule.match = CurLink;
    CurLink = NULL;
    parse_vars_reset();
  }
  | T_MATCH protocol_msgtype protocol_field cmpdata {
#ifdef DEBUG
    printf("==== match_section\n");
#endif
    CurLink = match_add(CurLink, &CurMatch, Logic);
    while (CurLink && CurLink->parent)
      CurLink = CurLink->parent;
#ifdef DEBUG
    match_node_dump_deep(CurLink, 0);
#endif
    CurRule.match = CurLink;
    CurLink = NULL;
    parse_vars_reset();
  }
  ;

  /* TODO: merge nearly identical code blocks */
protocol_msgtype:
  protocol_name ':' T_IDENTIFIER {
    const struct pkttype_match *m;
    strlcpy(PktType, $1.token, sizeof PktType);
    strlcat(PktType, ":", sizeof PktType);
    strlcat(PktType, $3.token, sizeof PktType);
#ifdef DEBUG
    printf("protocol_msgtype(%s)\n", PktType);
#endif
    m = pkttype_match_str(PktType);
    CurRule.pkt = m->pkt;
    CurRule.type = m->type;
#ifdef DEBUG
    printf("pkt:%u, type:%u\n", CurRule.pkt, CurRule.type);
#endif
    PktType[0] = '\0';
  }
  | protocol_name {
    const struct pkttype_match *m;
    strlcpy(PktType, $1.token, sizeof PktType);
#ifdef DEBUG
    printf("protocol_msgtype(%s)\n", PktType);
#endif
    m = pkttype_match_str(PktType);
    CurRule.pkt = m->pkt;
    CurRule.type = m->type;
#ifdef DEBUG
    printf("pkt:%u, type:%u\n", CurRule.pkt, CurRule.type);
#endif
    PktType[0] = '\0';
  }
  ;

protocol_field:
  protocol_field_piece {
#ifdef DEBUG
    printf("protocol_field(%s)\n", PktField);
#endif
    CurMatch.fieldmap = pktfield_get_map_str(PktField);
    if (NULL == CurMatch.fieldmap) {
      fprintf(stderr, "Invalid field '%s'\n", PktField);
      abort();
    }
  }
  ;

protocol_field_piece:
  protocol_name '.' field_identifier {
    strlcpy(PktField, $1.token, sizeof PktField);
    strlcat(PktField, ".", sizeof PktField);
    strlcat(PktField, $3.token, sizeof PktField);
  }
  | protocol_field_piece '.' field_identifier {
    strlcat(PktField, ".", sizeof PktField);
    strlcat(PktField, $3.token, sizeof PktField);
  }
  ;

assert_section:
  T_ASSERT assert_match {
    while (CurLink && CurLink->parent)
      CurLink = CurLink->parent;
    CurRule.assert = CurLink;
#ifdef DEBUG
    match_node_dump_deep(CurLink, 0);
#endif
    CurLink = NULL;
    parse_vars_reset();
  }
  ;

assert_match:
  assert_submatch {
#ifdef DEBUG
    printf("^^^ 1 match\n");
#endif
    CurLink = match_add(CurLink, &CurMatch, Logic);
#ifdef DEBUG
    match_node_dump_deep(CurLink, 0);
#endif
    parse_vars_reset();
  }
  | '(' assert_match ')' 
  | assert_match logic_op assert_match /* this causes 2 shift/reduce conflicts */
  ;

assert_submatch:
  protocol_field cmpdata
  ;

cmpdata:
  cmp_scalar data_scalar
  | cmp_list data_list
  ;

cmp_scalar:
  T_NEQ           { CurMatch.op = CMP_EQL; CurMatch.negate = 1; }
  | negate T_EQL  { CurMatch.op = CMP_EQL; }
  | T_IS negate   { CurMatch.op = CMP_EQL; }
  | negate T_GT   { CurMatch.op = CMP_GT; }
  | negate T_LT   { CurMatch.op = CMP_LT; }
  | negate T_GTE  { CurMatch.op = CMP_GTE; }
  | negate T_LTE  { CurMatch.op = CMP_LTE; }
  ;

cmp_list:
  negate T_IN {
    CurMatch.op = CMP_IN;
  }
  ;

data:
  data_scalar
  | data_list
  ;

data_scalar:
  T_VARNAME {
    const struct var *v = alias_lookup($1.token);
    if (NULL == v) {
      fprintf(stderr, "VAR '%s' does not exist!\n", $1.token);
      exit(EXIT_FAILURE);
    }
    CurMatch.datatype = v->type;
    memcpy(&CurMatch.data, &v->data, sizeof CurMatch.data);
  }
  | T_IPADDR {
    CurMatch.datatype = TYPE_IP;
    iplist_append_str(&CurMatch.data.ips, $1.token);
  }
  | T_MACADDR {
    CurMatch.datatype = TYPE_MAC;
    maclist_append_str(&CurMatch.data.macs, $1.token);
  }
  | T_INTEGER {
    CurMatch.datatype = TYPE_INT;
    intlist_append(&CurMatch.data.ints, $1.i);
  }
  | T_STR {
    CurMatch.datatype = TYPE_STRING;
    (void)strlunescape($1.token, $1.token + 1, strlen($1.token) - 1);
    strlist_append(&CurMatch.data.strs, $1.token, strlen($1.token));
  }
  ;

data_list:
  '[' list_data ']' 
  | '[' ']' 
  | T_VARNAME {
    const struct var *v = alias_lookup($1.token);
    if (NULL == v) {
      fprintf(stderr, "VAR '%s' does not exist!\n", $1.token);
      exit(EXIT_FAILURE);
    }
    CurMatch.datatype = v->type;
    memcpy(&CurMatch.data, &v->data, sizeof CurMatch.data);
  }
  ;

list_data:
  list_ips {
    CurMatch.datatype = TYPE_IP;
#ifdef DEBUG
    iplist_dump(&CurMatch.data.ips);
#endif
  }
  | list_macs {
    CurMatch.datatype = TYPE_MAC;
#ifdef DEBUG
    maclist_dump(&CurMatch.data.macs);
#endif
  }
  | list_ints {
    CurMatch.datatype = TYPE_INT;
#ifdef DEBUG
    intlist_dump(&CurMatch.data.ints);
#endif
  }
  | list_strs {
    CurMatch.datatype = TYPE_STRING;
#ifdef DEBUG
    intlist_dump(&CurMatch.data.strs);
#endif
  }
  ;

list_ips:
  T_IPADDR {
    iplist_append_str(&CurMatch.data.ips, $1.token);
  }
  | list_ips T_IPADDR {
    iplist_append_str(&CurMatch.data.ips, $2.token);
  }
  ;

list_macs:
  T_MACADDR {
    maclist_append_str(&CurMatch.data.macs, $1.token);
  }
  | list_macs T_MACADDR {
    maclist_append_str(&CurMatch.data.macs, $2.token);
  }
  ;

list_ints:
  T_INTEGER {
    intlist_append(&CurMatch.data.ints, $1.i);
  }
  | list_ints T_INTEGER {
    intlist_append(&CurMatch.data.ints, $2.i);
  }
  ;

list_strs:
  T_STR {
    (void)strlunescape($1.token, $1.token + 1, strlen($1.token) - 1);
    strlist_append(&CurMatch.data.strs, $1.token, strlen($1.token));
  }
  | list_strs T_STR {
    (void)strlunescape($2.token, $2.token + 1, strlen($2.token) - 1);
    strlist_append(&CurMatch.data.strs, $2.token, strlen($2.token));
  }
  ;

negate: /* optional negation */
  T_NOT {
#ifdef DEBUG
    printf("negated\n");
#endif
    CurMatch.negate = !CurMatch.negate;
  }
  | { CurMatch.negate = 0; }/* not negated */
  ;

field_identifier:
  T_IP
  | T_IDENTIFIER
  ;

protocol_name:
  T_ETH     { Protocol = ETH; }
  | T_ARP   { Protocol = ARP; }
  | T_IP    { Protocol = IP;  }
  | T_ICMP  { Protocol = ICMP; }
  | T_UDP   { Protocol = UDP; }
  | T_TCP   { Protocol = TCP; }
  | T_DNS   { Protocol = DNS; }
  | T_BOOTP { Protocol = BOOTP; }
  | T_NBNS  { Protocol = NBNS; }
  | T_LLC   { Protocol = LLC; }
  | T_CDP   { Protocol = CDP; }
  | T_STP   { Protocol = STP; }
  | T_DTP   { Protocol = DTP; }
  | T_NBDGM { Protocol = NBDGM; }
  | T_SNMP  { Protocol = SNMP;  }
  | T_IP6   { Protocol = IP6;  }
  | T_IGMP  { Protocol = IGMP;  }
  | T_WTF   { }
  ;

'\n' { Lineno++; }

%%

extern FILE *yyin;
extern int yyparse();

static void parse_vars_reset(void)
{
  PktType[0] = '\0';
  PktField[0] = '\0';
  VarName[0] = '\0';
  match_node_init(&CurMatch);
  /* leave CurLink alone! */
  Logic = LOGIC_OR;
  /* leave Rule_Disabled alone, we handle it elsewhere */
}

#ifdef PARSE_STANDALONE
int main(int argc, char *argv[])
{
  yydebug = 1;
  do {
    yyparse();
  } while (!feof(yyin));
  rule_dump(&CurRule);
  printf("Rules loaded.\n");
  return 0;
}
#else
void parse_config(void)
{
  FILE *f;
  extern const char *ConfigFile;
  Lineno = 1; /* reset in case we're called more than once */
  yydebug = 1;
  f = fopen(ConfigFile, "r");
  if (NULL == f) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }
  yyin = f;
  do {
    yyparse();
  } while (!feof(yyin));
  printf("Rules loaded.\n");
  fclose(yyin);
}
extern void parse_cmdline();
extern void iface_loop();
extern void init_data();
int main(int argc, char *argv[])
{
  parse_cmdline(argc, argv);
  init_data();
  parse_config();
  iface_loop();
  return 0;
}
#endif

void yyerror(const char *errmsg)
{
  extern const char *ConfigFile;
  fflush(stdout);
  fprintf(stderr, "%s: %s on line %lu near '%s'\n",
    ConfigFile, errmsg, Lineno, yytext);
  exit(EXIT_FAILURE);
}

int yywrap(void)
{
  return 1;
}

