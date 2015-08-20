SOURCES=Config.pm Status.pm Snapshot.pm

.PHONY: install
install:
	install -d -m 0755 ${PERLDIR}/PVE/API2/LXC
	for i in ${SOURCES}; do install -D -m 0644 $$i ${PERLDIR}/PVE/API2/LXC/$$i; done


