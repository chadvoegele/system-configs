# Maintainer: Chad Voegele <cavoegele@gmail.com>
_pkgname=system-configs
pkgname=${_pkgname}-git
pkgver=1.1
pkgrel=1
pkgdesc='system config'
arch=('any')
url='https://github.com/chadvoegele/system-configs'
license=('GPL')
backup=()
source=('git+https://github.com/chadvoegele/system-configs.git')
md5sums=('SKIP')

install_pkg() {
  if [[ -z "$1" ]]
  then
    echo "install_pkg requires directory parameter."
  else
    DIREC="$1"
  fi

  for FILE in $(find ${DIREC} -type f -name "*.pkg")
  do
    FILE_SRC=${FILE}
    FILE_DEST_PKG="/"${FILE_SRC#*/}
    FILE_DEST=${FILE_DEST_PKG%.*}
    backup+=(${FILE_DEST})
    install -m 644 -D ${FILE_SRC} ${pkgdir}/${FILE_DEST}
  done
}

package() {
  cd ${srcdir}/${_pkgname}
  install_pkg "any"
  install_pkg ${HOSTNAME}
}
