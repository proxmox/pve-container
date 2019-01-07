PACKAGE=pve-container
PKGVER != dpkg-parsechangelog -Sversion | cut -d- -f1
PKGREL != dpkg-parsechangelog -Sversion | cut -d- -f2

GITVERSION:=$(shell git rev-parse HEAD)

ARCH:=all

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_${ARCH}.deb

all: ${DEB}

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}

.PHONY: deb
deb: ${DEB}
${DEB}:
	rm -rf build
	mkdir build
	rsync -a src/ build
	rsync -a debian/ build/debian
	echo "git clone git://git.proxmox.com/git/pve-container\\ngit checkout ${GITVERSION}" > build/debian/SOURCE
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEB}

.PHONY: clean
clean:
	make -C src clean
	rm -rf build *.deb ${PACKAGE}-*.tar.gz *.changes *.buildinfo
	find . -name '*~' -exec rm {} ';'

.PHONY: distclean
distclean: clean

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh -X repoman@repo.proxmox.com -- upload --product pve --dist stretch
