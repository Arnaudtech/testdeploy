#!/bin/bash

set -e

#############################################################################
#                                                                           #
# Project 'pterodactyl-installer-Zkillu'                                           #
#                                                                           #
#############################################################################

SCRIPT_VERSION="v0.0.1"
GITHUB_BASE_URL="https://raw.githubusercontent.com/Arnaudtech/pterodactyl-installation-zkillu"

LOG_PATH="/var/log/pterodactyl-zkillu.log"

# sortir avec une erreur si l'utilisateur n'est pas root
if [[ $EUID -ne 0 ]]; then
  echo "* Ce script doit être exécuté avec les privilèges de l'utilisateur root (sudo)." 1>&2
  exit 1
fi

# check for curl
if ! [ -x "$(command -v curl)" ]; then
  echo "* curl est requis pour utiliser ce script."
  echo "* S'il n'est pas présent sur le système, une mise à jour système va être effectuée et ensuite l'installation de curl"
  echo "* Merci de patienter 10 secondes."
  sleep 10
  apt update -q -y && apt upgrade -y
  apt-get install curl
  echo "* Curl vient d'être installé sur votre machine"
  sleep 5
fi

output() {
  echo -e "* ${1}"
}

error() {
  COLOR_RED='\033[0;31m'
  COLOR_NC='\033[0m'

  echo ""
  echo -e "* ${COLOR_RED}ERROR${COLOR_NC}: $1"
  echo ""
}

execute() {
  echo -e "\n\n* pterodactyl-installer $(date) \n\n" >> $LOG_PATH

  bash <(curl -s "$1") | tee -a $LOG_PATH
  [[ -n $2 ]] && execute "$2"
}

done=false

output "Pterodactyl installation by Zkillu @ $SCRIPT_VERSION"
output
output "Copyright (C) 2020 - 2022, Arno"
output
output "Ce script est utilisé pour installer Pterodactyl pour les clients Zkillu."

output

PANEL_LATEST="$install-panel.sh"

WINGS_LATEST="$curl -sSL https://raw.githubusercontent.com/tommytran732/Anti-DDOS-Iptables/master/javapipe_kernel.sh"

while [ "$done" == false ]; do
  options=(
    "Installation du Panel"
    "Installation des Wings"
    "Installez [0] et [1] sur la même machine (le script des wings est exécuté après le panel).\n"
  )

  actions=(
    "$PANEL_LATEST"
    "$WINGS_LATEST"
    "$PANEL_LATEST;$WINGS_LATEST"
  )

  output "Que voulez vous faire ?"

  for i in "${!options[@]}"; do
    output "[$i] ${options[$i]}"
  done

  echo -n "* Input 0-$((${#actions[@]} - 1)): "
  read -r action

  [ -z "$action" ] && error "Input is required" && continue

  valid_input=("$(for ((i = 0; i <= ${#actions[@]} - 1; i += 1)); do echo "${i}"; done)")
  [[ ! " ${valid_input[*]} " =~ ${action} ]] && error "Invalid option"
  [[ " ${valid_input[*]} " =~ ${action} ]] && done=true && IFS=";" read -r i1 i2 <<< "${actions[$action]}" && execute "$i1" "$i2"
done
