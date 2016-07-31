include commands.mk

CFLAGS  := -std=c99 -fPIC -Wall
LDFLAGS :=

SRC  = $(wildcard *.c)
OBJ  = $(foreach obj, $(SRC:.c=.o), $(notdir $(obj)))
DEP  = $(SRC:.c=.d)

TARGETS     = wimip wimipd

SERVER_OBJ = wimipd.o help.o xatoi.o version.o
CLIENT_OBJ = wimip.o help.o safe-call.o version.o common.o xatoi.o time-substract.o scale.o af-str.o

PREFIX  ?= /usr/local
BIN     ?= /bin
SBIN    ?= /sbin

commit = $(shell ./hash.sh)
ifneq ($(commit), UNKNOWN)
	CFLAGS += -DCOMMIT="\"$(commit)\""
	CFLAGS += -DPARTIAL_COMMIT="\"$(shell echo $(commit) | cut -c1-8)\""
endif

ifndef DISABLE_DEBUG
CFLAGS += -ggdb -O0
else
CFLAGS += -DNDEBUG=1 -O2
endif

.PHONY: all clean

all: $(TARGETS)

wimipd: $(SERVER_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

wimip: $(CLIENT_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -Wp,-MMD,$*.d -c $(CFLAGS) -o $@ $<

clean:
	$(RM) $(DEP)
	$(RM) $(OBJ)
	$(RM) $(CATALOGS)
	$(RM) $(TARGETS)

install:
	$(MKDIR) -p $(DESTDIR)/$(PREFIX)/$(BIN)
	$(INSTALL_PROGRAM) wimipd $(DESTDIR)/$(PREFIX)/$(SBIN)
	$(INSTALL_PROGRAM) wimip $(DESTDIR)/$(PREFIX)/$(BIN)

uninstall:
	$(RM) $(DESTDIR)/$(PREFIX)/$(SBIN)/wimipd
	$(RM) $(DESTDIR)/$(PREFIX)/$(BIN)/wimip

-include $(DEP)
