PACKAGE=pve-container

PREFIX=$(DESTDIR)/usr
BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib
SBINDIR=$(PREFIX)/sbin
ETCDIR=$(DESTDIR)/etc
MANDIR=$(PREFIX)/share/man
DOCDIR=$(PREFIX)/share/doc/$(PACKAGE)
LXC_SCRIPT_DIR=$(PREFIX)/share/lxc
LXC_TMPL_DIR=$(LXC_SCRIPT_DIR)/templates
LXC_HOOK_DIR=$(LXC_SCRIPT_DIR)/hooks
LXC_CONFIG_DIR=$(LXC_SCRIPT_DIR)/config
LXC_COMMON_CONFIG_DIR=$(LXC_CONFIG_DIR)/common.conf.d
LXC_USERNS_CONFIG_DIR=$(LXC_CONFIG_DIR)/userns.conf.d
SERVICEDIR=$(DESTDIR)/lib/systemd/system
APPARMORDDIR=$(ETCDIR)/apparmor.d
PODDIR=$(DOCDIR)/pod
MAN1DIR=$(MANDIR)/man1/
MAN5DIR=$(MANDIR)/man5/
BASHCOMPLDIR=$(PREFIX)/share/bash-completion/completions/
ZSHCOMPLDIR=$(PREFIX)/share/zsh/vendor-completions/
export PERLDIR=$(PREFIX)/share/perl5

# this require package pve-doc-generator
export NOVIEW=1
include /usr/share/pve-doc-generator/pve-doc-generator.mk

all:

pct.bash-completion:
	PVE_GENERATING_DOCS=1 perl -I. -T -e "use PVE::CLI::pct; PVE::CLI::pct->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

pct.zsh-completion:
	PVE_GENERATING_DOCS=1 perl -I. -T -e "use PVE::CLI::pct; PVE::CLI::pct->generate_zsh_completions();" >$@.tmp
	mv $@.tmp $@

.PHONY: check
check: test
	make -C test

.PHONY: install
install: pct lxc-pve.conf pct.1 pct.conf.5 pct.bash-completion pct.zsh-completion \
    pve-userns.seccomp pve-container@.service pve-container-debug@.service \
    lxc-pve-prestart-hook lxc-pve-autodev-hook lxc-pve-poststop-hook lxcnetaddbr
	PVE_GENERATING_DOCS=1 perl -I. -T -e "use PVE::CLI::pct; PVE::CLI::pct->verify_api();"
	install -d $(SBINDIR)
	install -m 0755 pct $(SBINDIR)
	install -d $(LXC_SCRIPT_DIR)
	install -m 0755 lxcnetaddbr $(LXC_SCRIPT_DIR)
	install -m 0755 pve-container-stop-wrapper $(LXC_SCRIPT_DIR)
	install -d -m0755 $(SERVICEDIR)
	install -m0644 pve-container@.service $(SERVICEDIR)/
	install -m0644 pve-container-debug@.service $(SERVICEDIR)/
	install -m0644 'system-pve\x2dcontainer.slice' $(SERVICEDIR)/
	install -d $(LXC_HOOK_DIR)
	install -m 0755 lxc-pve-prestart-hook $(LXC_HOOK_DIR)
	install -m 0755 lxc-pve-autodev-hook $(LXC_HOOK_DIR)
	install -m 0755 lxc-pve-poststop-hook $(LXC_HOOK_DIR)
	install -d $(LXC_CONFIG_DIR)
	install -m 0644 pve-userns.seccomp $(LXC_CONFIG_DIR)/pve-userns.seccomp
	install -d $(LXC_COMMON_CONFIG_DIR)
	install -m 0644 lxc-pve.conf $(LXC_COMMON_CONFIG_DIR)/01-pve.conf
	install -d $(LXC_USERNS_CONFIG_DIR)
	install -m 0644 lxc-pve-userns.conf $(LXC_USERNS_CONFIG_DIR)/01-pve.conf
	install -m 0644 -D pct.bash-completion $(BASHCOMPLDIR)/pct
	install -m 0644 -D pct.zsh-completion $(ZSHCOMPLDIR)/_pct
	make -C PVE install
	install -d $(MAN1DIR)
	install -d $(MAN5DIR)
	install -m 0644 pct.1 $(MAN1DIR)
	gzip -9 $(MAN1DIR)/pct.1
	install -m 0644 pct.conf.5 $(MAN5DIR)
	gzip -9 $(MAN5DIR)/pct.conf.5
	cd $(MAN5DIR); ln -s pct.conf.5.gz ct.conf.5.gz
	install -D -m 0644 10-pve-ct-inotify-limits.conf $(LIBDIR)/sysctl.d/10-pve-ct-inotify-limits.conf
	install -D -m 0644 pve-container-mounthotplug $(APPARMORDDIR)/pve-container-mounthotplug

pve-userns.seccomp: /usr/share/lxc/config/common.seccomp
	cp $< $@
	echo 'keyctl errno 38' >> $@

.PHONY: test
test:
	make -C test test

.PHONY: clean
clean: 	
	make -C test clean
	make cleanup-docgen
	rm -f *.1 *.5 *.tmp *.bash-completion *.bash-completion

.PHONY: distclean
distclean: clean

