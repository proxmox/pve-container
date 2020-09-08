SOURCES= \
	CGroup.pm \
	Command.pm \
	Config.pm \
	Create.pm \
	Migrate.pm \
	Monitor.pm \
	Setup.pm \
	Tools.pm

.PHONY: install
install: ${SOURCES} 
	install -d -m 0755 ${PERLDIR}/PVE/LXC
	for i in ${SOURCES}; do install -D -m 0644 $$i ${PERLDIR}/PVE/LXC/$$i; done
	make -C Setup install


