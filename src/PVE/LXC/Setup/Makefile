SOURCES=\
    Plugin.pm		\
    Base.pm		\
    Alpine.pm		\
    ArchLinux.pm	\
    CentOS.pm		\
    Debian.pm		\
    Devuan.pm		\
    Fedora.pm		\
    Gentoo.pm		\
    SUSE.pm		\
    Ubuntu.pm		\
    NixOS.pm		\
    Unmanaged.pm	\

.PHONY: install
install:
	install -d -m 0755 ${PERLDIR}/PVE/LXC/Setup
	for i in ${SOURCES}; do install -D -m 0644 $$i ${PERLDIR}/PVE/LXC/Setup/$$i; done
