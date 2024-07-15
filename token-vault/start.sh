#!/bin/bash
source .env

function help {
  echo "
OPTIONS:
  (at least one must be specified)

  -c, --compile
    compile the project using \"make x64\"
  -u, --upload
    compile the coff to the windows ssh server
  -r, --run
    run the coff of the windows ssh server
  -i, --interactive
    get an interactive shell on the machine, not compatible with --run.
    this one has priority over --run.
"
}

if [[ $# -eq 0 ]]; then
  help
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      help
      exit
      ;;
    -u|--upload)
      upload="true"
      shift 1
      ;;
    -c|--compile)
      compile="true"
      shift 1
      ;;
    -r|--run)
      run="true"
      shift 1
      ;;
    -i|--interactive)
      interactive="true"
      shift 1
      ;;
    *)
      echo "error: invalid argument $1"
      exit 1
      ;;
  esac
done

if [[ "$compile" == "true" ]]; then
  make x64

  if [[ "$?" != 0 ]]; then
    upload="false"
    run="false"
  fi
fi

if [[ "$upload" == "true" ]]; then
  echo "[*] Uploading the coff"
  #sshpass -p "$SSH_SERVER_PASSWORD" scp bin/token-vault.x64.o "${SSH_SERVER_USERNAME}@${SSH_SERVER_IP}:C:/SharedFolder/"
  mv bin/token-vault.x64.o ~/SharedFolder/

  if [[ "$?" != 0 ]]; then
    run="false"
    echo "[-] failed to upload the coff on the machine"
  fi
fi

if [[ "$interactive" == "true" ]]; then
  sshpass -p "$SSH_SERVER_PASSWORD" ssh "${SSH_SERVER_USERNAME}@${SSH_SERVER_IP}"
elif [[ "$run" == "true" ]]; then
  echo "[*] Running the coff"
  #sshpass -p "$SSH_SERVER_PASSWORD" ssh "${SSH_SERVER_USERNAME}@${SSH_SERVER_IP}" "C:/SharedFolder/CoffeeLdr.x64.exe go C:/SharedFolder/token-vault.x64.o"
  sshpass -p "$SSH_SERVER_PASSWORD" ssh "${SSH_SERVER_USERNAME}@${SSH_SERVER_IP}" "\\\\host.lan\\Data\\CoffeeLdr.x64.exe go \\\\host.lan\\Data\\token-vault.x64.o"
fi
