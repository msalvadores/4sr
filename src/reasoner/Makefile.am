AM_CFLAGS = -Wall -g -std=gnu99 -O2 -I.. -DGIT_REV=@GIT_REV@ @RAPTOR_CFLAGS@ @GLIB_CFLAGS@ @MDNS_CFLAGS@
AM_LDFLAGS = -lz @GLIB_LIBS@ @GTHREAD_LIBS@

noinst_LIBRARIES = lib4sreasoner.a

noinst_HEADERS = 4s-reasoner-common.h 4s-reasoner-backend.h 4s-reasoner-query.h

LIB_OBJS = 4s-reasoner-common.o 4s-reasoner-query.o 4s-reasoner-backend.o 

lib4sreasoner_a_SOURCES = 4s-reasoner-common.c 4s-reasoner-query.c 4s-reasoner-backend.c 
