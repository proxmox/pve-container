SOURCES=Base.pm Debian.pm Ubuntu.pm Redhat.pm Fedora.pm ArchLinux.pm

.PHONY: install
install:
	install -d -m 0755 ${PERLDIR}/PVE/LXC/Setup
	for i in ${SOURCES}; do install -D -m 0644 $$i ${PERLDIR}/PVE/LXC/Setup/$$i; done
