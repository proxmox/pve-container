PACKAGE=pve-container

PREFIX=${DESTDIR}/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc/${PACKAGE}
LXC_SCRIPT_DIR=${PREFIX}/share/lxc
LXC_TMPL_DIR=${LXC_SCRIPT_DIR}/templates
LXC_HOOK_DIR=${LXC_SCRIPT_DIR}/hooks
LXC_COMMON_CONFIG_DIR=${LXC_SCRIPT_DIR}/config/common.conf.d
PODDIR=${DOCDIR}/pod
MAN1DIR=${MANDIR}/man1/
MAN5DIR=${MANDIR}/man5/
export PERLDIR=${PREFIX}/share/perl5

all:

%.1.gz: %.1.pod
	rm -f $@
	cat $<|pod2man -n $* -s 1 -r ${VERSION} -c "Proxmox Documentation"|gzip -c9 >$@

%.5.gz: %.5.pod
	rm -f $@
	cat $<|pod2man -n $* -s 5 -r ${VERSION} -c "Proxmox Documentation"|gzip -c9 >$@

pct.1.pod: pct
	perl -I. -T ./pct printmanpod >$@

pct.conf.5.pod: gen-pct-conf-pod.pl PVE/LXC.pm
	perl -I. ./gen-pct-conf-pod.pl >$@

lxc-pve-mount-hook.1.pod: lxc-pve-mount-hook
	perl -I. -T ./lxc-pve-mount-hook printmanpod >$@

lxc-pve-poststop-hook.1.pod: lxc-pve-poststop-hook
	perl -I. -T ./lxc-pve-poststop-hook printmanpod >$@

.PHONY: install
install: pct lxc-pve.conf lxc-pve-mount-hook lxc-pve-poststop-hook lxcnetaddbr lxc-pve-mount-hook.1.pod lxc-pve-mount-hook.1.gz lxc-pve-poststop-hook.1.pod lxc-pve-poststop-hook.1.gz pct.1.pod pct.1.gz pct.conf.5.pod pct.conf.5.gz pve-update-lxc-config
	perl -T -I. ./pct verifyapi
	install -d ${SBINDIR}
	install -m 0755 pct ${SBINDIR}
	install -m 0755 pve-update-lxc-config ${SBINDIR}
	install -d ${LXC_SCRIPT_DIR}
	install -m 0755 lxcnetaddbr ${LXC_SCRIPT_DIR}
	install -d ${LXC_HOOK_DIR}
	install -m 0755 lxc-pve-mount-hook ${LXC_HOOK_DIR}
	install -m 0755 lxc-pve-poststop-hook ${LXC_HOOK_DIR}
	install -d ${LXC_COMMON_CONFIG_DIR}
	install -m 0644 lxc-pve.conf ${LXC_COMMON_CONFIG_DIR}/01-pve.conf
	make -C PVE install
	install -d ${MAN1DIR}
	install -d ${MAN5DIR}
	install -d ${PODDIR}
	install -m 0644 pct.1.gz ${MAN1DIR}
	install -m 0644 pct.1.pod ${PODDIR}
	install -m 0644 pct.conf.5.pod ${PODDIR}
	install -m 0644 pct.conf.5.gz ${MAN5DIR}

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

