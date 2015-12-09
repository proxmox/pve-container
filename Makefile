RELEASE=4.1

VERSION=1.0
PACKAGE=pve-container
PKGREL=33

GITVERSION:=$(shell cat .git/refs/heads/master)

ARCH:=all

DEB=${PACKAGE}_${VERSION}-${PKGREL}_${ARCH}.deb

all: ${DEB}

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}

.PHONY: deb ${DEB}
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
	umount /pve/${RELEASE}; mount /pve/${RELEASE} -o rw 
	mkdir -p /pve/${RELEASE}/extra
	rm -f /pve/${RELEASE}/extra/${PACKAGE}_*.deb
	rm -f /pve/${RELEASE}/extra/Packages*
	cp ${DEB} /pve/${RELEASE}/extra
	cd /pve/${RELEASE}/extra; dpkg-scanpackages . /dev/null > Packages; gzip -9c Packages > Packages.gz
	umount /pve/${RELEASE}; mount /pve/${RELEASE} -o ro

