#!/bin/bash
set -e

declare -r myname='config_deploy'
declare -r wireguard_public_key_prefix='PUBLIC_KEY_'

if [[ -z ${HOSTNAME} ]]
then
  echo "HOSTNAME not set!" >&2
  exit 1
fi

replace_wireguard_public_keys() {
  local FILE="$1"
  local KEY_FILE PEER_HOST PUBLIC_KEY PUBLIC_KEY_TOKEN

  for KEY_FILE in *.lan/etc/wireguard/wg0.public.key
  do
    PEER_HOST=${KEY_FILE%%/*}
    PUBLIC_KEY=$(<"${KEY_FILE}")
    PUBLIC_KEY_TOKEN=${wireguard_public_key_prefix}${PEER_HOST}

    if grep -qF "PublicKey = ${PUBLIC_KEY_TOKEN}" "${FILE}"
    then
      if [[ ! ${PUBLIC_KEY} =~ ^[A-Za-z0-9+/]{43}=$ ]]
      then
        echo "Invalid WireGuard public key in ${KEY_FILE}" >&2
        return 1
      fi
      sed -i "s|^PublicKey = ${PUBLIC_KEY_TOKEN}$|PublicKey = ${PUBLIC_KEY}|" "${FILE}"
    fi
  done

  if grep -q "^PublicKey = ${wireguard_public_key_prefix}" "${FILE}"
  then
    echo "Missing WireGuard public key for ${FILE}" >&2
    return 1
  fi
}

redact_wireguard_public_keys() {
  local FILE="$1"
  local KEY_FILE PEER_HOST PUBLIC_KEY PUBLIC_KEY_TOKEN

  for KEY_FILE in *.lan/etc/wireguard/wg0.public.key
  do
    PEER_HOST=${KEY_FILE%%/*}
    PUBLIC_KEY=$(<"${KEY_FILE}")
    PUBLIC_KEY_TOKEN=${wireguard_public_key_prefix}${PEER_HOST}

    if [[ ${PUBLIC_KEY} =~ ^[A-Za-z0-9+/]{43}=$ ]]
    then
      sed -i "s|^PublicKey = ${PUBLIC_KEY}$|PublicKey = ${PUBLIC_KEY_TOKEN}|" "${FILE}"
    fi
  done

  if grep '^PublicKey = ' "${FILE}" | grep -qv "^PublicKey = ${wireguard_public_key_prefix}"
  then
    echo "Missing WireGuard public key for ${FILE}" >&2
    return 1
  fi
}

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
    if [[ ${FILE} == */etc/wireguard/wg0.public.key ]]
    then
      continue
    fi

    FILE_SRC=${FILE}
    FILE_DEST="${CONFIG_ROOT}/"${FILE_SRC#*/}

    if [[ ${FORCE} == 1 ]]
    then
      DEST_DIR=$(dirname ${FILE_DEST})
      if [[ ! -e "${DEST_DIR}" ]]
      then
        mkdir "${DEST_DIR}"
      fi

      if [[ ${FILE_SRC} == */etc/wireguard/wg0.conf ]]
      then
        TMP_FILE=$(mktemp)
        cp -p "${FILE_SRC}" "${TMP_FILE}"

        if ! replace_wireguard_public_keys "${TMP_FILE}"
        then
          rm -f "${TMP_FILE}"
          exit 1
        fi

        cp -p "${TMP_FILE}" "${FILE_DEST}"
        rm -f "${TMP_FILE}"
      else
        cp -p "${FILE_SRC}" "${FILE_DEST}"
      fi

      if [[ ${FILE_SRC} == */etc/wireguard/wg0.conf || ${FILE_SRC} == */etc/wireguard/wg0.private.key ]]
      then
        chmod 600 "${FILE_DEST}"
      fi
      echo "Ran: cp -p ${FILE_SRC} ${FILE_DEST}"
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
    if [[ ${FILE} == */etc/wireguard/wg0.public.key ]]
    then
      continue
    fi

    FILE_DEST=${FILE}
    FILE_SRC="${CONFIG_ROOT}/"${FILE_DEST#*/}
    if [[ ${FORCE} == 0 ]]
    then
      echo "For ${DIREC}, would run: cp -p ${FILE_SRC} ${FILE_DEST}"
    elif [[ -e ${FILE_SRC} ]]
    then
      if [[ ${FILE_DEST} == */etc/wireguard/wg0.conf ]]
      then
        TMP_FILE=$(mktemp)
        cp -p "${FILE_SRC}" "${TMP_FILE}"

        if ! redact_wireguard_public_keys "${TMP_FILE}"
        then
          rm -f "${TMP_FILE}"
          exit 1
        fi

        cp -p "${TMP_FILE}" "${FILE_DEST}"
        rm -f "${TMP_FILE}"
      else
        cp -p "${FILE_SRC}" "${FILE_DEST}"
      fi
      echo "Ran: cp -p ${FILE_SRC} ${FILE_DEST}"
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
    if [[ ${FILE} == */etc/wireguard/wg0.public.key ]]
    then
      continue
    fi

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
