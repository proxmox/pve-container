SOURCES=Base.pm Debian.pm Ubuntu.pm CentOS.pm Fedora.pm SUSE.pm ArchLinux.pm Alpine.pm Gentoo.pm Devuan.pm

.PHONY: install
install:
	install -d -m 0755 ${PERLDIR}/PVE/LXC/Setup
	for i in ${SOURCES}; do install -D -m 0644 $$i ${PERLDIR}/PVE/LXC/Setup/$$i; done
