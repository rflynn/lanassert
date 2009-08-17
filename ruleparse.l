/* $Id$ */
/* ex: set ts=2 et: */

%{
#include "y.tab.h"
#include "rule.h"
#include "util.h"
#define COPY_TOKEN  strlcpy(yylval.token, yytext, sizeof yylval.token)
%}

whitespace      [ \t\r\v\f]
newline         [\n]
octet           (25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])
hexdigit        [0-9A-Fa-f]
hexoctet        [0-9A-Fa-f][0-9A-Fa-f]
identifier      [A-Z_][A-Z0-9_]+

%%

NOT     { return T_NOT; }
IN      { return T_IN; }
IS      { return T_IS; }
==      { return T_EQL; }
!=      { return T_NEQ; }
[>]     { return T_GT; }
[<]     { return T_LT; }
[>]=    { return T_GTE; }
[<]=    { return T_LTE; }

AND     { return T_AND; }
OR      { return T_OR; }

RULE    {
#ifdef DEBUG
  printf("RULE(%s)\n", yytext);
#endif
  return T_RULE;
}
EXPLAIN { return T_EXPLAIN; }
DISABLED { return T_DISABLE; }
ALARM   { return T_ALARM; }
MATCH   { return T_MATCH; }
ASSERT  { return T_ASSERT; }
EMAIL   { return T_EMAIL; }
AUDIO   { return T_AUDIO; }
VAR     { return T_VAR; }
BREAK   { return T_BREAK; }

ETH     { COPY_TOKEN; return T_ETH;   }
ARP     { COPY_TOKEN; return T_ARP;   }
BOOTP   { COPY_TOKEN; return T_BOOTP; }
ICMP    { COPY_TOKEN; return T_ICMP;  }
IP      { COPY_TOKEN; return T_IP;    }
IP4     { COPY_TOKEN; return T_IP;    }
UDP     { COPY_TOKEN; return T_UDP;   }
DNS     { COPY_TOKEN; return T_DNS;   }
TCP     { COPY_TOKEN; return T_TCP;   }
NBNS    { COPY_TOKEN; return T_NBNS;  }
SMB     { COPY_TOKEN; return T_SMB;   }
LLC     { COPY_TOKEN; return T_LLC;   }
CDP     { COPY_TOKEN; return T_CDP;   }
STP     { COPY_TOKEN; return T_STP;   }
DTP     { COPY_TOKEN; return T_DTP;   }
NBDGM   { COPY_TOKEN; return T_NBDGM; }
SNMP    { COPY_TOKEN; return T_SNMP;  }
IP6     { COPY_TOKEN; return T_IP6;   }
IGMP    { COPY_TOKEN; return T_IGMP;  }
WTF     { return T_WTF; }

[$]{identifier} {
  COPY_TOKEN;
#if 0
  printf("VARNAME(%s)->(%s)\n", yytext, yylval.token);
#endif
  return T_VARNAME;
}

{identifier} {
  COPY_TOKEN;
#if 0
  printf("IDENTIFIER(%s)->(%s)\n", yytext, yylval.token);
#endif
  return T_IDENTIFIER;
}

["]([^\n"]+|[\\]["])*["] {
  /* string */
  COPY_TOKEN;
#ifdef DEBUG
  printf("STRING(%s)\n", yytext);
#endif
  return T_STR;
}

[#][^\n]* {
  /* comment */
#ifdef DEBUG
  printf("COMMENT(%s)\n", yytext);
#endif
}

[#]begin[.\n]*[#]end {
  /* comment */
#ifdef DEBUG
  printf("COMMENT(%s)\n", yytext);
#endif
}

{octet}[\.]{octet}[\.]{octet}[\.]{octet}([/][0-9]+)? {
  /* IP with optional mask */
  COPY_TOKEN;
#ifdef DEBUG
  printf("IP(%s)\n", yytext);
#endif
  return T_IPADDR;
}

{hexoctet}[:]{hexoctet}[:]{hexoctet}[:]{hexoctet}[:]{hexoctet}[:]{hexoctet} {
  /* MAC address */
  strcpy(yylval.token, yytext);
#ifdef DEBUG
  printf("MACADDR(%s)\n", yytext);
#endif
  return T_MACADDR;
}

0x[0-9A-Fa-f]+ {
  yylval.i = strtol(yytext, NULL, 16);
  return T_INTEGER;
}

[0-9]+ {
  yylval.i = strtol(yytext, NULL, 10);
  return T_INTEGER;
}

{whitespace}+ {
  /* skip... */
#if 0
  printf("WHITESPACE(%s)\n", yytext);
#endif
}

{newline} {
  extern unsigned long Lineno;
  Lineno++;
}

. { return yytext[0]; }

%%

