VERSION=1.0
PACKAGE=pve-container
PKGREL=77

GITVERSION:=$(shell cat .git/refs/heads/master)

ARCH:=all

DEB=${PACKAGE}_${VERSION}-${PKGREL}_${ARCH}.deb

all: ${DEB}

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}

.PHONY: deb
deb ${DEB}:
	rm -rf build
	mkdir build
	rsync -a src/ build
	rsync -a debian/ build/debian
	echo "git clone git://git.proxmox.com/git/pve-container\\ngit checkout ${GITVERSION}" > build/debian/SOURCE
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian ${DEB}

.PHONY: clean
clean:
	make -C src clean
	rm -rf build *.deb ${PACKAGE}-*.tar.gz *.changes 
	find . -name '*~' -exec rm {} ';'

.PHONY: distclean
distclean: clean

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload
