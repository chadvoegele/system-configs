#!/bin/bash

declare -r myname='config_deploy'

deploy_non_pkg() {
  if [[ -z "$1" ]]
  then
    echo "deploy requires directory parameter."
  else
    DIREC="$1"
  fi

  for FILE in $(find ${DIREC} -type f -not -name "*.pkg")
  do
    FILE_SRC=${FILE}
    FILE_DEST="/"${FILE_SRC#*/}
    pacman -Qoq ${FILE_DEST} 1>/dev/null 2>/dev/null
    if [[ $? -eq 0 ]]; then
      cp -p ${FILE_SRC} ${FILE_DEST}
    else
      echo "No package owns ${FILE_DEST}. Not installing!"
    fi
  done
}

deploy_non_pkg_all() {
  deploy_non_pkg "any"
  deploy_non_pkg ${HOSTNAME}
}

reverse_deploy() {
  if [[ -z "$1" ]]
  then
    echo "reverse_deploy requires directory parameter."
  else
    DIREC="$1"
  fi

  if [[ ! -d "${DIREC}" ]]
  then
    echo "${DIREC} does not exist! Skipping..."
    return
  fi

  for FILE in $(find ${DIREC} -type f -not -name "*.pkg")
  do
    FILE_DEST=${FILE}
    FILE_SRC="/"${FILE_DEST#*/}
    if [[ -e ${FILE_SRC} ]]; then
      cp -p ${FILE_SRC} ${FILE_DEST}
    fi
  done

  for FILE in $(find ${DIREC} -type f -name "*.pkg")
  do
    FILE_DEST=${FILE}
    FILE_SRC_PKG="/"${FILE_DEST#*/}
    FILE_SRC=${FILE_SRC_PKG%.*}
    if [[ -e ${FILE_SRC} ]]; then
      cp -p ${FILE_SRC} ${FILE_DEST}
    fi
  done
}

reverse_deploy_all() {
  reverse_deploy "any"
  reverse_deploy ${HOSTNAME}
}

usage() {
	cat <<EOF
Usage: $myname [-d | -r]

Options:
  -d/--deploy        deploy non ".pkg" system configs
  -r/--reverse       copy system configs back to repo for updating
EOF
}

while [[ -n "$1" ]]; do
	case "$1" in
		-d|--deploy)
			DEPLOY=1;;
		-r|--reverse)
			REVERSE=1;;
		-h|--help)
			usage; exit 0;;
		*)
			usage; exit 1;;
	esac
	shift
done

if [[ $DEPLOY ]]; then
  deploy_non_pkg_all
elif [[ $REVERSE ]]; then
 reverse_deploy_all
else
  usage
fi
