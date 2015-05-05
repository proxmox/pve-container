SOURCES=Base.pm Debian.pm Redhat.pm

.PHONY: install
install:
	install -d -m 0755 ${PERLDIR}/PVE/LXCSetup
	for i in ${SOURCES}; do install -D -m 0644 $$i ${PERLDIR}/PVE/LXCSetup/$$i; done
