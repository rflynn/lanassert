# $Id$

CFLAGS_DEBUG = -O0 -ggdb -pg -DYYDEBUG=0 -DDEBUG=1
CFLAGS = -W -Wall -Wno-unused -Os -pipe
LDFLAGS = -lpcap
LDFLAGS_DEBUG = -pg
FLEX = flex -I
YACC = yacc
INSTALL = install
prefix = /usr/local
BINARY = LANassert
BINDEST = ${prefix}/bin/
DATADEST = ${prefix}/share/LANassert/


LANassert: y.tab.o lex.yy.o LANassert.o prot.o rule.o type.o util.o

debug:
	$(MAKE) CFLAGS="$(CFLAGS) $(CFLAGS_DEBUG)" LDFLAGS="$(LDFLAGS) $(LDFLAGS_DEBUG)"

prot.o: prot.h type.h util.h
rule.o: rule.h type.h util.h
util.o: util.h

lex.yy.o: lex.yy.c

y.tab.c y.tab.h: ruleparse.y
	$(YACC) -d ruleparse.y

lex.yy.c: ruleparse.l
	$(LEX) ruleparse.l

install:
	$(INSTALL) -m 0755 -d $(BINDEST)
	$(INSTALL) -m 0755 $(BINARY) $(BINDEST)

uninstall:
	$(RM) $(BINDEST)$(BINARY)

clean:
	$(RM) *.o LANassert ruleparse *.tab.[ch] lex.yy.c cscope.out y.output

ruleparse: y.tab.o lex.yy.o type.o prot.o rule.o util.o
	$(CC) -o ruleparse y.tab.o lex.yy.o type.o prot.o rule.o util.o -lfl -lm

parse:
	$(MAKE) CFLAGS="$(CFLAGS) -DPARSE_STANDALONE" ruleparse

