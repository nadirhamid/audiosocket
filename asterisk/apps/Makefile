#
# Makefile for Asterisk AudioSocket application
# borrowed from Asterisk-eSpeak makefile
#
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the COPYING file
# at the top of the source tree.

ASTLIBDIR:=$(shell awk '/moddir/{print $$3}' /etc/asterisk/asterisk.conf 2> /dev/null)
ifeq ($(strip $(ASTLIBDIR)),)
	MODULES_DIR:=$(INSTALL_PREFIX)/usr/lib/asterisk/modules
else
	MODULES_DIR:=$(INSTALL_PREFIX)$(ASTLIBDIR)
endif
ASTETCDIR:=$(INSTALL_PREFIX)/etc/asterisk
SAMPLENAME:=audiosocket.conf.sample
CONFNAME:=$(basename $(SAMPLENAME))

INSTALL:=install
CC:=gcc
OPTIMIZE:=-O2
DEBUG:=-g

#LIBS+=-
CFLAGS+=-pipe -fPIC -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -D_REENTRANT -D_GNU_SOURCE -DAST_MODULE_SELF_SYM=__internal_app_audiosocket_self

all: app_audiosocket.so
	@echo " +-------- app_audiosocket Build Complete --------+"
	@echo " + app_audiosocket has successfully been built,   +"
	@echo " + and can be installed by running:          +"
	@echo " +                                           +"
	@echo " +               make install                +"
	@echo " +-------------------------------------------+"

app_audiosocket.o: app_audiosocket.c
	$(CC) $(CFLAGS) $(DEBUG) $(OPTIMIZE) -c -o $@ $*.c

app_audiosocket.so: app_audiosocket.o
	$(CC) -shared -Xlinker -x -o $@ $< $(LIBS)

clean:
	rm -f app_audiosocket.o app_audiosocket.so

install: all
	$(INSTALL) -m 755 -d $(DESTDIR)$(MODULES_DIR)
	$(INSTALL) -m 755 app_audiosocket.so $(DESTDIR)$(MODULES_DIR)
	@echo " +---- app_audiosocket Installation Complete -----+"
	@echo " +                                           +"
	@echo " + app_audiosocket has successfully been installed+"
	@echo " + If you would like to install the sample   +"
	@echo " + configuration file run:                   +"
	@echo " +                                           +"
	@echo " +              make samples                 +"
	@echo " +-------------------------------------------+"

samples:
	@mkdir -p $(DESTDIR)$(ASTETCDIR)
	@if [ -f $(DESTDIR)$(ASTETCDIR)/$(CONFNAME) ]; then \
		echo "Backing up previous config file as $(CONFNAME).old";\
		mv -f $(DESTDIR)$(ASTETCDIR)/$(CONFNAME) $(DESTDIR)$(ASTETCDIR)/$(CONFNAME).old ; \
	fi ;
	$(INSTALL) -m 644 $(SAMPLENAME) $(DESTDIR)$(ASTETCDIR)/$(CONFNAME)
	@echo " ------- app_esepak confing Installed --------"
