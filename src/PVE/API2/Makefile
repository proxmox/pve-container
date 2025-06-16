SOURCES=LXC.pm

.PHONY: install
install:
	install -d -m 0755 $(PERLDIR)/PVE/API2
	for i in $(SOURCES); do install -D -m 0644 $$i $(PERLDIR)/PVE/API2/$$i; done
	make -C LXC install

