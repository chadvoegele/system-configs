#!/bin/bash
set -e

declare -r myname='config_deploy'

if [[ -z ${HOSTNAME} ]]
then
  echo "HOSTNAME not set!" >&2
  exit 1
fi

deploy() {
  local FORCE=0

  if [[ -z "$1" ]]
  then
    echo "deploy requires directory parameter." >&2
    exit 1
  else
    DIREC="$1"
  fi

  if [[ -n "$2" ]]
  then
    FORCE="$2"
  fi

  for FILE in $(find ${DIREC} -type f)
  do
    FILE_SRC=${FILE}
    FILE_DEST="/"${FILE_SRC#*/}

    if [[ ${FORCE} == 1 ]]
    then
      DEST_DIR=$(dirname ${FILE_DEST})
      if [[ ! -e "${DEST_DIR}" ]]
      then
        mkdir "${DEST_DIR}"
      fi
      cp -p "${FILE_SRC}" "${FILE_DEST}"
    else
      echo "For ${DIREC}, would run: cp -p ${FILE_SRC} ${FILE_DEST}"
    fi
  done
}

deploy_all() {
  local FORCE="$1"
  deploy "any" "${FORCE}"
  deploy ${HOSTNAME} "${FORCE}"
}

reverse_deploy() {
  local FORCE=0

  if [[ -z "$1" ]]
  then
    echo "reverse_deploy requires directory parameter." >&2
    exit 1
  else
    DIREC="$1"
  fi

  if [[ -n "$2" ]]
  then
    FORCE="$2"
  fi

  if [[ ! -d "${DIREC}" ]]
  then
    echo "${DIREC} does not exist! Skipping..."
    return
  fi

  for FILE in $(find ${DIREC} -type f)
  do
    FILE_DEST=${FILE}
    FILE_SRC="/"${FILE_DEST#*/}
    if [[ ${FORCE} == 0 ]]
    then
      echo "For ${DIREC}, would run: cp -p ${FILE_SRC} ${FILE_DEST}"
    elif [[ -e ${FILE_SRC} ]]
    then
      cp -p ${FILE_SRC} ${FILE_DEST}
    else
      echo "${FILE_SRC} does not exist!"
    fi
  done
}

reverse_deploy_all() {
  local FORCE="$1"
  reverse_deploy "any" "${FORCE}"
  reverse_deploy ${HOSTNAME} "${FORCE}"
}

notlost() {
  if [[ -z "$1" ]]
  then
    echo "notlost requires directory parameter." >&2
    exit 1
  else
    DIREC="$1"
  fi

  for FILE in $(find ${DIREC} -type f)
  do
    FILE_SRC=${FILE}
    FILE_DEST="/"${FILE_SRC#*/}

    echo ${FILE_DEST}
  done
}

notlost_all() {
  notlost "any"
  notlost ${HOSTNAME}
}

usage() {
	cat <<EOF
Usage: $myname [-d | -r | -f]

Options:
  -d/--deploy        deploy system configs
  -r/--reverse       copy system configs back to repo for updating
  -n/--notlost       print files that are tracked to ignore in lostfiles
  -f/--force         no dry run, actually copy
EOF
}

FORCE=0

while [[ -n "$1" ]]; do
	case "$1" in
		-d|--deploy)
			DEPLOY=1;;
		-r|--reverse)
			REVERSE=1;;
		-n|--notlost)
			NOTLOST=1;;
		-f|--force)
			FORCE=1;;
		-h|--help)
			usage; exit 0;;
		*)
			usage; exit 1;;
	esac
	shift
done

if [[ ${FORCE} == 1 ]]
then
  echo "Running in copy mode" >&2
else
  echo "Running in dry run mode" >&2
fi

if [[ $DEPLOY ]]; then
  deploy_all "${FORCE}"
elif [[ $REVERSE ]]; then
  reverse_deploy_all "${FORCE}"
elif [[ $NOTLOST ]]; then
  notlost_all
else
  usage
fi
