include ../rev.mk
include ../darwin.mk
include ../discovery.mk


pkgs = glib-2.0 $(avahi)

ifdef avahi
  mdns_flags = -DUSE_AVAHI
endif
ifdef dnssd
  mdns_flags = -DUSE_DNS_SD
endif

CFLAGS = -Wall -g -std=gnu99 -O2 -I.. -DGIT_REV=\"$(gitrev)\" -lpthread -DUSE_REASONER $(mdns_flags) `pkg-config --cflags $(pkgs)`
#CFLAGS = -Wall -g -std=gnu99 -I.. -DGIT_REV=\"$(gitrev)\" $(mdns_flags) `pkg-config --cflags raptor glib-2.0`
LDFLAGS = $(ldfdarwin) $(ldflinux) -lz -lpthread `pkg-config --libs $(pkgs)`

LIB_OBJS = 4s-reasoner-common.o 4s-reasoner-query.o 4s-reasoner-backend.o
HEADERS = 4s-reasoner-common.h 4s-reasoner-query.h 4s-reasoner-backend.h
BINS = 4s-reasoner

all: $(BINS)

install:
	mkdir -p $(DESTDIR)/usr/local/bin/
	install $(BINS) $(DESTDIR)/usr/local/bin/

clean: 
	rm -f $(BINS) lib4sreasoner.a *.o

4s-reasoner: ../common/lib4store.a lib4sreasoner.a 4s-reasoner.o

lib4sreasoner.a: $(LIB_OBJS) $(HEADERS)
	ar rvu lib4sreasoner.a $(LIB_OBJS)
	ranlib lib4sreasoner.a
