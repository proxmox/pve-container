PACKAGE=pve-container

PREFIX=${DESTDIR}/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc/${PACKAGE}
LXCSCRIPTDIR=${PREFIX}/share/lxc
LXCTMPLDIR=${LXCSCRIPTDIR}/templates
LXCHOOKDIR=${LXCSCRIPTDIR}/hooks
PODDIR=${DOCDIR}/pod
MAN1DIR=${MANDIR}/man1/
export PERLDIR=${PREFIX}/share/perl5

all:

%.1.gz: %.1.pod
	rm -f $@
	cat $<|pod2man -n $* -s 1 -r ${VERSION} -c "Proxmox Documentation"|gzip -c9 >$@

pct.1.pod: pct
	perl -I. -T ./pct printmanpod >$@

lxc-pve.1.pod: lxc-pve
	perl -I. -T ./lxc-pve printmanpod >$@

lxc-pve-mount-hook.1.pod: lxc-pve-mount-hook
	perl -I. -T ./lxc-pve-mount-hook printmanpod >$@

.PHONY: install
install: pct lxc-pve lxc-pve-mount-hook lxcnetaddbr lxc-pve-mount-hook.1.pod lxc-pve-mount-hook.1.gz pct.1.pod pct.1.gz lxc-pve.1.pod lxc-pve.1.gz
	perl -T -I. ./pct verifyapi
	perl -T -I. ./lxc-pve verifyapi
	install -d ${SBINDIR}
	install -m 0755 pct ${SBINDIR}
	install -d ${LXCSCRIPTDIR}
	install -m 0755 lxcnetaddbr ${LXCSCRIPTDIR}
	install -d ${LXCTMPLDIR}
	install -m 0755 lxc-pve ${LXCTMPLDIR}
	install -d ${LXCHOOKDIR}
	install -m 0755 lxc-pve-mount-hook ${LXCHOOKDIR}
	make -C PVE install
	install -d ${MAN1DIR}
	install -d ${PODDIR}
	install -m 0644 pct.1.gz ${MAN1DIR}
	install -m 0644 lxc-pve.1.gz ${MAN1DIR}
	install -m 0644 pct.1.pod ${PODDIR}
	install -m 0644 lxc-pve.1.pod ${PODDIR}

.PHONY: test
test:
	make -C test test

.PHONY: clean
clean: 	
	make -C test clean
	rm -rf *.1.pod *.1.gz
	find . -name '*~' -exec rm {} ';'

.PHONY: distclean
distclean: clean

