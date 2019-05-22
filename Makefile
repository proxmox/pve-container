include /usr/share/dpkg/pkg-info.mk

PACKAGE=pve-container

GITVERSION:=$(shell git rev-parse HEAD)
BUILDDIR ?= ${PACKAGE}-${DEB_VERSION_UPSTREAM}

DEB=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}_all.deb
DSC=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}.dsc

all: ${DEB}

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}

${BUILDDIR}:
	rm -rf ${BUILDDIR}
	rsync -a src/ debian ${BUILDDIR}
	echo "git clone git://git.proxmox.com/git/pve-container\\ngit checkout ${GITVERSION}" > build/debian/SOURCE

.PHONY: deb
deb: ${DEB}
${DEB}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -b -us -uc
	lintian ${DEB}


.PHONY: dsc
dsc: ${DSC}
${DSC}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -S -us -uc -d -nc
	lintian ${DSC}

.PHONY: clean
clean:
	make -C src clean
	rm -rf *.deb ${PACKAGE}*.tar.gz *.changes *.buildinfo ${DSC} ${PACKAGE}-*/
	find . -name '*~' -exec rm {} ';'

.PHONY: distclean
distclean: clean

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh -X repoman@repo.proxmox.com -- upload --product pve --dist stretch
