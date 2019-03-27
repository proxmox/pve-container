PACKAGE=pve-container
PKGVER != dpkg-parsechangelog -Sversion | cut -d- -f1
PKGREL != dpkg-parsechangelog -Sversion | cut -d- -f2

GITVERSION:=$(shell git rev-parse HEAD)
BUILDDIR ?= build

ARCH:=all

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_${ARCH}.deb
DSC=${PACKAGE}_${PKGVER}-${PKGREL}.dsc

all: ${DEB}

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}

${BUILDDIR}:
	rm -rf ${BUILDDIR}
	rsync -a src/ ${BUILDDIR}
	rsync -a debian ${BUILDDIR}/
	echo "git clone git://git.proxmox.com/git/pve-container\\ngit checkout ${GITVERSION}" > build/debian/SOURCE

.PHONY: deb
deb: ${DEB}
${DEB}: ${BUILDDIR}
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEB}


.PHONY: dsc
dsc: ${DSC}
${DSC}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -S -us -uc -d -nc
	lintian ${DSC}

.PHONY: clean
clean:
	make -C src clean
	rm -rf *.deb ${PACKAGE}*.tar.gz *.changes *.buildinfo ${DSC} ${BUILDDIR}
	find . -name '*~' -exec rm {} ';'

.PHONY: distclean
distclean: clean

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh -X repoman@repo.proxmox.com -- upload --product pve --dist stretch
