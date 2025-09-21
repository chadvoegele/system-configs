#!/bin/bash
set -e

declare -r myname='config_deploy'

deploy() {
  local FORCE=0

  if [[ -z "$1" ]]
  then
    echo "deploy requires directory parameter."
  else
    DIREC="$1"
  fi

  if [[ -z "$2" ]]
  then
    FORCE="$2"
  fi

  for FILE in $(find ${DIREC} -type f)
  do
    FILE_SRC=${FILE}
    FILE_DEST="/"${FILE_SRC#*/}

    if [[ ${FORCE} == 1 ]]
    then
      cp -p ${FILE_SRC} ${FILE_DEST}
    else
      echo cp -p ${FILE_SRC} ${FILE_DEST}
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
    echo "reverse_deploy requires directory parameter."
  else
    DIREC="$1"
  fi

  if [[ -z "$2" ]]
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
    if [[ ${FORCE} == 1 ]]
    then
      cp -p ${FILE_SRC} ${FILE_DEST}
    else
      echo cp -p ${FILE_SRC} ${FILE_DEST}
    fi
  done
}

reverse_deploy_all() {
  local FORCE="$1"
  reverse_deploy "any" "${FORCE}"
  reverse_deploy ${HOSTNAME} "${FORCE}"
}

usage() {
	cat <<EOF
Usage: $myname [-d | -r | -f]

Options:
  -d/--deploy        deploy system configs
  -r/--reverse       copy system configs back to repo for updating
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
  echo "Running in copy mode"
else
  echo "Running in dry run mode"
fi

if [[ $DEPLOY ]]; then
  deploy_all "${FORCE}"
elif [[ $REVERSE ]]; then
 reverse_deploy_all "${FORCE}"
else
  usage
fi
