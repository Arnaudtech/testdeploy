#!/bin/bash

set -e

#############################################################################
#                                                                           #
# Project 'pterodactyl-installer' for wings                                 #
#                                                                           #
# Copyright (C) 2018 - 2022, Vilhelm Prytz, <vilhelm@prytznet.se>           #
#                                                                           #
#   This program is free software: you can redistribute it and/or modify    #
#   it under the terms of the GNU General Public License as published by    #
#   the Free Software Foundation, either version 3 of the License, or       #
#   (at your option) any later version.                                     #
#                                                                           #
#   This program is distributed in the hope that it will be useful,         #
#   but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#   GNU General Public License for more details.                            #
#                                                                           #
#   You should have received a copy of the GNU General Public License       #
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                           #
# https://github.com/vilhelmprytz/pterodactyl-installer/blob/master/LICENSE #
#                                                                           #
# This script is not associated with the official Pterodactyl Project.      #
# https://github.com/vilhelmprytz/pterodactyl-installer                     #
#                                                                           #
#############################################################################

# versioning
GITHUB_SOURCE="master"
SCRIPT_RELEASE="canary"

#################################
######## General checks #########
#################################

# exit with error status code if user is not root
if [[ $EUID -ne 0 ]]; then
  echo "* Ce script doit être lancé en root." 1>&2
  su root
fi

# check for curl
if ! [ -x "$(command -v curl)" ]; then
  echo "* curl est requis pour utiliser ce script."
  echo "* S'il n'est pas présent sur le système, une mise à jour système va être effectuée et ensuite l'installation de curl"
  echo "* Merci de patienter 15 secondes."
  sleep 15
  apt update -q -y && apt upgrade -y
  apt-get install curl
  echo "* Curl vient d'être installé sur votre machine"
  sleep 5
fi

#################################
########## Variables ############
#################################

# download URLs
WINGS_DL_BASE_URL="https://github.com/pterodactyl/wings/releases/latest/download/wings_linux_"
GITHUB_BASE_URL="https://raw.githubusercontent.com/Arnaudtech/pterodactyl-installation-zkillu/$GITHUB_SOURCE"

COLOR_RED='\033[0;31m'
COLOR_NC='\033[0m'

INSTALL_MARIADB=false

# firewall
CONFIGURE_FIREWALL=false
CONFIGURE_UFW=false
CONFIGURE_FIREWALL_CMD=false
CONFIGURE_IPTABLES=false

# SSL (Let's Encrypt)
CONFIGURE_LETSENCRYPT=false
FQDN=""
EMAIL=""

# Database host
CONFIGURE_DBHOST=false
CONFIGURE_DBEXTERNAL=false
CONFIGURE_DBEXTERNAL_HOST="%"
CONFIGURE_DB_FIREWALL=false
MYSQL_DBHOST_USER="pterodactyluser"
MYSQL_DBHOST_PASSWORD="password"

# regex for email input
regex="^(([A-Za-z0-9]+((\.|\-|\_|\+)?[A-Za-z0-9]?)*[A-Za-z0-9]+)|[A-Za-z0-9]+)@(([A-Za-z0-9]+)+((\.|\-|\_)?([A-Za-z0-9]+)+)*)+\.([A-Za-z]{2,})+$"

#################################
####### Vérification de la version ########
#################################

get_latest_release() {
  curl --silent "https://api.github.com/repos/$1/releases/latest" | # Get latest release from GitHub api
    grep '"tag_name":' |                                            # Get tag line
    sed -E 's/.*"([^"]+)".*/\1/'                                    # Pluck JSON value
}

echo "* Récupération des informations..."
WINGS_VERSION="$(get_latest_release "pterodactyl/wings")"

####### Other library functions ########

valid_email() {
  [[ $1 =~ ${regex} ]]
}

required_input() {
  local __resultvar=$1
  local result=''

  while [ -z "$result" ]; do
    echo -n "* ${2}"
    read -r result

    if [ -z "${3}" ]; then
      [ -z "$result" ] && result="${4}"
    else
      [ -z "$result" ] && print_error "${3}"
    fi
  done

  eval "$__resultvar="'$result'""
}

password_input() {
  local __resultvar=$1
  local result=''
  local default="$4"

  while [ -z "$result" ]; do
    echo -n "* ${2}"

    # modified from https://stackoverflow.com/a/22940001
    while IFS= read -r -s -n1 char; do
      [[ -z $char ]] && {
        printf '\n'
        break
      }                               # ENTER pressed; output \n and break.
      if [[ $char == $'\x7f' ]]; then # backspace was pressed
        # Only if variable is not empty
        if [ -n "$result" ]; then
          # Remove last char from output variable.
          [[ -n $result ]] && result=${result%?}
          # Erase '*' to the left.
          printf '\b \b'
        fi
      else
        # Add typed char to output variable.
        result+=$char
        # Print '*' in its stead.
        printf '*'
      fi
    done
    [ -z "$result" ] && [ -n "$default" ] && result="$default"
    [ -z "$result" ] && print_error "${3}"
  done

  eval "$__resultvar="'$result'""
}

#################################
####### Visual functions ########
#################################

print_error() {
  echo ""
  echo -e "* ${COLOR_RED}ERROR${COLOR_NC}: $1"
  echo ""
}

print_warning() {
  COLOR_YELLOW='\033[1;33m'
  COLOR_NC='\033[0m'
  echo ""
  echo -e "* ${COLOR_YELLOW}WARNING${COLOR_NC}: $1"
  echo ""
}

print_brake() {
  for ((n = 0; n < $1; n++)); do
    echo -n "#"
  done
  echo ""
}

hyperlink() {
  echo -e "\e]8;;${1}\a${1}\e]8;;\a"
}

#################################
####### OS check funtions #######
#################################

detect_distro() {
  if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$(echo "$ID" | awk '{print tolower($0)}')
    OS_VER=$VERSION_ID
  elif type lsb_release >/dev/null 2>&1; then
    # linuxbase.org
    OS=$(lsb_release -si | awk '{print tolower($0)}')
    OS_VER=$(lsb_release -sr)
  elif [ -f /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    . /etc/lsb-release
    OS=$(echo "$DISTRIB_ID" | awk '{print tolower($0)}')
    OS_VER=$DISTRIB_RELEASE
  elif [ -f /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    OS="debian"
    OS_VER=$(cat /etc/debian_version)
  elif [ -f /etc/SuSe-release ]; then
    # Older SuSE/etc.
    OS="SuSE"
    OS_VER="?"
  elif [ -f /etc/redhat-release ]; then
    # Older Red Hat, CentOS, etc.
    OS="Red Hat/CentOS"
    OS_VER="?"
  else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
    OS_VER=$(uname -r)
  fi

  OS=$(echo "$OS" | awk '{print tolower($0)}')
  OS_VER_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
}

check_os_comp() {
  SUPPORTED=false

  MACHINE_TYPE=$(uname -m)
  case "$MACHINE_TYPE" in
  x86_64)
    ARCH=amd64
    ;;
  arm64) ;&
    # fallthrough
  aarch64)
    print_warning "Architecture détectée : arm64"
    print_warning "Vous devrez utiliser des images Docker spécialement conçues pour arm64. Si vous ne comprennez pas ce problème, Merci de contacter Arno#7570"
    echo -e -n "* Etes vous sur de vouloir continuer? (y/N):"
    read -r choice

    if [[ ! "$choice" =~ [Yy] ]]; then
      print_error "Installation annulée !"
      exit 1
    fi
    ARCH=arm64
    ;;
  *)
    print_error "Seulement x86_64 et arm64 sont supporté pour le service Wings"
    exit 1
    ;;
  esac

  case "$OS" in
  ubuntu)
    [ "$OS_VER_MAJOR" == "18" ] && SUPPORTED=true
    [ "$OS_VER_MAJOR" == "20" ] && SUPPORTED=true
    ;;
  debian)
    [ "$OS_VER_MAJOR" == "9" ] && SUPPORTED=true
    [ "$OS_VER_MAJOR" == "10" ] && SUPPORTED=true
    [ "$OS_VER_MAJOR" == "11" ] && SUPPORTED=true
    ;;
  centos)
    [ "$OS_VER_MAJOR" == "7" ] && SUPPORTED=true
    [ "$OS_VER_MAJOR" == "8" ] && SUPPORTED=true
    ;;
  *)
    SUPPORTED=false
    ;;
  esac

  # exit if not supported
  if [ "$SUPPORTED" == true ]; then
    echo "* $OS $OS_VER is supported."
  else
    echo "* $OS $OS_VER is not supported"
    print_error "Unsupported OS"
    exit 1
  fi

  # check virtualization
  echo -e "* Installing virt-what..."
  if [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
    # silence dpkg output
    export DEBIAN_FRONTEND=noninteractive

    # install virt-what
    apt-get -y update -qq
    apt-get install -y virt-what -qq

    # unsilence
    unset DEBIAN_FRONTEND
  elif [ "$OS" == "centos" ]; then
    if [ "$OS_VER_MAJOR" == "7" ]; then
      yum -q -y update

      # install virt-what
      yum -q -y install virt-what
    elif [ "$OS_VER_MAJOR" == "8" ]; then
      dnf -y -q update

      # install virt-what
      dnf install -y -q virt-what
    fi
  else
    print_error "Invalid OS."
    exit 1
  fi

  virt_serv=$(virt-what)

  case "$virt_serv" in
  *openvz* | *lxc*)
    print_warning "Une version de virtualization incompatible est détectée. Veuillez consulter votre fournisseur d'hébergement pour savoir si votre serveur peut exécuter Docker ou non."
    echo -e -n "* Etes vous sur de vouloir continuer (y/N): "
    read -r CONFIRM_PROCEED
    if [[ ! "$CONFIRM_PROCEED" =~ [Yy] ]]; then
      print_error "Installation aborted!"
      exit 1
    fi
    ;;
  *)
    [ "$virt_serv" != "" ] && print_warning "Virtualization: $virt_serv detected."
    ;;
  esac

  if uname -r | grep -q "xxxx"; then
    print_error "Unsupported kernel detected."
    exit 1
  fi
}

############################
## INSTALLATION FUNCTIONS ##
############################

apt_update() {
  apt update -q -y && apt upgrade -y
}

yum_update() {
  yum -y update
}

dnf_update() {
  dnf -y upgrade
}

enable_docker() {
  systemctl start docker
  systemctl enable docker
}

install_docker() {
  echo "* Installing docker .."
  if [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
    # Install dependencies
    apt-get -y install \
      apt-transport-https \
      ca-certificates \
      gnupg2 \
      software-properties-common \
	  iptables

    # Add docker gpg key
    curl -fsSL https://download.docker.com/linux/"$OS"/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

    # Add docker repo
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$OS \
      $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

    # Install docker
    apt_update
    apt-get -y install docker-ce docker-ce-cli containerd.io

    # Make sure docker is enabled
    enable_docker

  elif [ "$OS" == "centos" ]; then
    if [ "$OS_VER_MAJOR" == "7" ]; then
      # Install dependencies for Docker
      yum install -y yum-utils device-mapper-persistent-data lvm2

      # Add repo to yum
      yum-config-manager \
        --add-repo \
        https://download.docker.com/linux/centos/docker-ce.repo

      # Install Docker
      yum install -y docker-ce docker-ce-cli containerd.io
    elif [ "$OS_VER_MAJOR" == "8" ]; then
      # Install dependencies for Docker
      dnf install -y dnf-utils device-mapper-persistent-data lvm2

      # Add repo to dnf
      dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo

      # Install Docker
      dnf install -y docker-ce docker-ce-cli containerd.io --nobest
    fi

    enable_docker
  fi

  echo "* Docker a maintenant été installé."
}

ptdl_dl() {
  echo "* Installation du service Wings .. "

  mkdir -p /etc/pterodactyl
  curl -L -o /usr/local/bin/wings "$WINGS_DL_BASE_URL$ARCH"

  chmod u+x /usr/local/bin/wings

  echo "* Terminé."
}

systemd_file() {
  echo "* Installation systemd service.."
  curl -o /etc/systemd/system/wings.service $GITHUB_BASE_URL/configs/wings.service
  systemctl daemon-reload
  systemctl enable wings
  echo "* Installation systemd service terminée!"
}

install_mariadb() {
  MARIADB_URL="https://downloads.mariadb.com/MariaDB/mariadb_repo_setup"

  case "$OS" in
  debian)
    if [ "$ARCH" == "aarch64" ]; then
      print_warning "MariaDB doesn't support Debian on arm64"
      return
    fi
    [ "$OS_VER_MAJOR" == "9" ] && curl -sS $MARIADB_URL | sudo bash
    apt install -y mariadb-server
    ;;
  ubuntu)
    [ "$OS_VER_MAJOR" == "18" ] && curl -sS $MARIADB_URL | sudo bash
    apt install -y mariadb-server
    ;;
  centos)
    [ "$OS_VER_MAJOR" == "7" ] && curl -sS $MARIADB_URL | bash
    [ "$OS_VER_MAJOR" == "7" ] && yum -y install mariadb-server
    [ "$OS_VER_MAJOR" == "8" ] && dnf install -y mariadb mariadb-server
    ;;
  esac

  systemctl enable mariadb
  systemctl start mariadb
}

ask_database_user() {
  echo -n "* Voulez-vous configurer automatiquement un utilisateur pour la base de données ? (y/N): "
  read -r CONFIRM_DBHOST

  if [[ "$CONFIRM_DBHOST" =~ [Yy] ]]; then
    ask_database_external
    CONFIGURE_DBHOST=true
  fi
}

ask_database_external() {
  echo -n "* Voulez-vous configurer MySQL pour qu'il soit accessible de l'extérieur ? (y/N): "
  read -r CONFIRM_DBEXTERNAL

  if [[ "$CONFIRM_DBEXTERNAL" =~ [Yy] ]]; then
    echo -n "* Entrez l'adresse du panel (vide si pas de domaine): "
    read -r CONFIRM_DBEXTERNAL_HOST
    if [ "$CONFIRM_DBEXTERNAL_HOST" != "" ]; then
      CONFIGURE_DBEXTERNAL_HOST="$CONFIRM_DBEXTERNAL_HOST"
    fi
    [ "$CONFIGURE_FIREWALL" == true ] && ask_database_firewall
    CONFIGURE_DBEXTERNAL=true
  fi
}

ask_database_firewall() {
  print_warning "Autoriser le trafic entrant sur le port 3306 (MySQL) peut potentiellement constituer un risque pour la sécurité, à moins que vous ne sachiez ce que vous faites !"
  echo -n "* Voulez-vous autoriser le trafic entrant sur le port 3306 ? (y/N): "
  read -r CONFIRM_DB_FIREWALL
  if [[ "$CONFIRM_DB_FIREWALL" =~ [Yy] ]]; then
    CONFIGURE_DB_FIREWALL=true
  fi
}

configure_mysql() {
  echo "* Performing MySQL queries.."

  if [ "$CONFIGURE_DBEXTERNAL" == true ]; then
    echo "* Création de l'utilisateur MySQL..."
    mysql -u root -e "CREATE USER '${MYSQL_DBHOST_USER}'@'${CONFIGURE_DBEXTERNAL_HOST}' IDENTIFIED BY '${MYSQL_DBHOST_PASSWORD}';"

    echo "* Mise a jour des privilèges.."
    mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_DBHOST_USER}'@'${CONFIGURE_DBEXTERNAL_HOST}' WITH GRANT OPTION;"
  else
    echo "* Création de l'utilisateur MySQL..."
    mysql -u root -e "CREATE USER '${MYSQL_DBHOST_USER}'@'127.0.0.1' IDENTIFIED BY '${MYSQL_DBHOST_PASSWORD}';"

    echo "* Mise a jour des privilèges.."
    mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_DBHOST_USER}'@'127.0.0.1' WITH GRANT OPTION;"
  fi

  echo "* Application des modifications"
  mysql -u root -e "FLUSH PRIVILEGES;"

  echo "* Changement de l'adresse de liaison MySQL.."

  if [ "$CONFIGURE_DBEXTERNAL" == true ]; then
    case "$OS" in
    debian | ubuntu)
      sed -i 's/127.0.0.1/0.0.0.0/g' /etc/mysql/mariadb.conf.d/50-server.cnf
      ;;
    centos)
      sed -ne 's/^#bind-address=0.0.0.0$/bind-address=0.0.0.0/' /etc/my.cnf.d/mariadb-server.cnf
      ;;
    esac
  
    systemctl restart mysqld
  fi

  echo "* MySQL est maintenant configuré !"
}

#################################
##### OS SPECIFIC FUNCTIONS #####
#################################

ask_letsencrypt() {
  if [ "$CONFIGURE_UFW" == false ] && [ "$CONFIGURE_FIREWALL_CMD" == false ]; then
    print_warning "Let's Encrypt nécessite l'ouverture du port 80/443 ! Vous avez choisi de ne pas configurer le pare-feu automatique ; utilisez-le à vos risques et périls (si le port 80/443 est fermé, le script échouera).!"
  fi

  print_warning "Vous ne pouvez pas utiliser Let's Encrypt avec votre nom d'hôte comme adresse IP ! Il doit s'agir d'un nom de domaine (par exemple, node.zkillu.fr)."

  echo -e -n "* Voulez-vous configurer automatiquement HTTPS en utilisant Let's Encrypt ? (y/N) : "
  read -r CONFIRM_SSL

  if [[ "$CONFIRM_SSL" =~ [Yy] ]]; then
    CONFIGURE_LETSENCRYPT=true
  fi
}

firewall_ufw() {
  apt install ufw -y

  echo -e "\n* Activation du pare-feu (UFW & IPtable)"
  echo "* Ouverture du port 22 (SSH), 8080 (Port Wings), 2022 (Port SFTP Wings)"

  # pointing to /dev/null silences the command output
  ufw allow ssh >/dev/null
  ufw allow 8080 >/dev/null
  ufw allow 2022 >/dev/null

  [ "$CONFIGURE_LETSENCRYPT" == true ] && ufw allow http >/dev/null
  [ "$CONFIGURE_LETSENCRYPT" == true ] && ufw allow https >/dev/null
  [ "$CONFIGURE_DB_FIREWALL" == true ] && ufw allow 3306 >/dev/null

  ufw --force enable
  ufw --force reload
  ufw status numbered | sed '/v6/d'
}

firewall_firewalld() {
  echo -e "\n* Enabling firewall_cmd (firewalld)"
  echo "* Opening port 22 (SSH), 8080 (Wings Port), 2022 (Wings SFTP Port)"

  # Install
  [ "$OS_VER_MAJOR" == "7" ] && yum -y -q install firewalld >/dev/null
  [ "$OS_VER_MAJOR" == "8" ] && dnf -y -q install firewalld >/dev/null

  # Enable
  systemctl --now enable firewalld >/dev/null # Enable and start

  # Configure
  firewall-cmd --add-service=ssh --permanent -q                                           # Port 22
  firewall-cmd --add-port 8080/tcp --permanent -q                                         # Port 8080
  firewall-cmd --add-port 2022/tcp --permanent -q                                         # Port 2022
  [ "$CONFIGURE_LETSENCRYPT" == true ] && firewall-cmd --add-service=http --permanent -q  # Port 80
  [ "$CONFIGURE_LETSENCRYPT" == true ] && firewall-cmd --add-service=https --permanent -q # Port 443
  [ "$CONFIGURE_DB_FIREWALL" == true ] && firewall-cmd --add-service=mysql --permanent -q # Port 3306

  firewall-cmd --permanent --zone=trusted --change-interface=pterodactyl0 -q
  firewall-cmd --zone=trusted --add-masquerade --permanent
  firewall-cmd --reload -q # Enable firewall

  echo "* Firewall-cmd installed"
  print_brake 70
  
}

firewall_iptables() {
  apt install iptables -y

  echo -e "\n* Activation du pare-feu (IPtable Fortement recommandé)"
  echo '=========================='
  echo "JavaPipe's kernel"
  echo '=========================='
  ### SSH brute-force protection ### 
  /sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
  /sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

  ### Protection against port scanning ### 
  /sbin/iptables -N port-scanning 
  /sbin/iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
  /sbin/iptables -A port-scanning -j DROP
  
  ### 1: Drop invalid packets ### 
  /sbin/iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP  

  ### 2: Drop TCP packets that are new and are not SYN ### 
  /sbin/iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP 
 
  ### 3: Drop SYN packets with suspicious MSS value ### 
  /sbin/iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP  

  ### 4: Block packets with bogus TCP flags ### 
  /sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
  /sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
  /sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
  /sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
  /sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
  /sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
  /sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP

  ### 5: Block spoofed packets ### 
  /sbin/iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP 
  /sbin/iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP 
  /sbin/iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP 
  /sbin/iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP 
  /sbin/iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
  /sbin/iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP 
  /sbin/iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP 
  /sbin/iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP 
  /sbin/iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP  

  ### 6: Drop ICMP (you usually don't need this protocol) ### 
  /sbin/iptables -t mangle -A PREROUTING -p icmp -j DROP  

  ### 7: Drop fragments in all chains ### 
  /sbin/iptables -t mangle -A PREROUTING -f -j DROP  

  ### 8: Limit connections per source IP ### 
  /sbin/iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset  

  ### 9: Limit RST packets ### 
  /sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
  /sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP  

  ### 10: Limit new TCP connections per second per source IP ### 
  /sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT 
  /sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP  

  ### 11: Use SYNPROXY on all ports (disables connection limiting rule) ### 
  iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack 
  iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 
  iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
  
  echo "JavaPipe's kernel Installed"
  
  sleep 5
  echo '=========================='
  echo "Allow ICMP OVH"
  echo '=========================='
  /sbin/iptables -A INPUT -i eth0 -p tcp --dport 22 --source cache.ovh.net -j ACCEPT
  /sbin/iptables -A INPUT -i eth0 -p icmp --source proxy.ovh.net -j ACCEPT
  /sbin/iptables -A INPUT -i eth0 -p icmp --source proxy.p19.ovh.net -j ACCEPT
  /sbin/iptables -A INPUT -i eth0 -p icmp --source proxy.rbx.ovh.net -j ACCEPT
  /sbin/iptables -A INPUT -i eth0 -p icmp --source proxy.sbg.ovh.net -j ACCEPT
  /sbin/iptables -A INPUT -i eth0 -p icmp --source proxy.bhs.ovh.net -j ACCEPT
  /sbin/iptables -A INPUT -i eth0 -p icmp --source ping.ovh.net -j ACCEPT
  /sbin/iptables -A INPUT -i eth0 -p icmp --source a2.ovh.net -j ACCEPT
  /sbin/iptables -A OUTPUT -p udp --dport 6100:6200 -j ACCEPT # OVH RTM
  echo "Allow OVH ICMP Installed"
}

letsencrypt() {
  FAILED=false

  # Install certbot
  case "$OS" in
  debian | ubuntu)
    apt-get -y install certbot python3-certbot-nginx
    ;;
  centos)
    [ "$OS_VER_MAJOR" == "7" ] && yum -y -q install epel-release
    [ "$OS_VER_MAJOR" == "7" ] && yum -y -q install certbot python-certbot-nginx

    [ "$OS_VER_MAJOR" == "8" ] && dnf -y -q install epel-release
    [ "$OS_VER_MAJOR" == "8" ] && dnf -y -q install certbot python3-certbot-nginx
    ;;
  esac

  # If user has nginx
  systemctl stop nginx || true

  # Obtain certificate
  certbot certonly --no-eff-email --email "$EMAIL" --standalone -d "$FQDN" || FAILED=true

  systemctl start nginx || true

  # Check if it succeded
  if [ ! -d "/etc/letsencrypt/live/$FQDN/" ] || [ "$FAILED" == true ]; then
    print_warning "Le processus d'obtention d'un certificat Let's Encrypt a échoué !"
  fi
}

####################
## MAIN FUNCTIONS ##
####################

perform_install() {
  echo "* Installing pterodactyl wings.."
  [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ] && apt_update
  [ "$OS" == "centos" ] && [ "$OS_VER_MAJOR" == "7" ] && yum_update
  [ "$OS" == "centos" ] && [ "$OS_VER_MAJOR" == "8" ] && dnf_update
  [ "$CONFIGURE_UFW" == true ] && firewall_ufw
  [ "$CONFIGURE_FIREWALL_CMD" == true ] && firewall_firewalld
  [ "$CONFIGURE_IPTABLES" == true ] && firewall_iptables
  install_docker
  ptdl_dl
  systemd_file
  [ "$INSTALL_MARIADB" == true ] && install_mariadb
  [ "$CONFIGURE_DBHOST" == true ] && configure_mysql
  [ "$CONFIGURE_LETSENCRYPT" == true ] && letsencrypt

  # return true if script has made it this far
  return 0
}

main() {
  # check if we can detect an already existing installation
  if [ -d "/etc/pterodactyl" ]; then
    print_warning "Le script a détecté que vous avez déjà des wings de Pterodactyl sur votre système ! Vous ne pouvez pas exécuter le script plusieurs fois, il échouera !"
    echo -e -n "* Êtes-vous sûr de vouloir continuer ? (y/N) : "
    read -r CONFIRM_PROCEED
    if [[ ! "$CONFIRM_PROCEED" =~ [Yy] ]]; then
      print_error "Installation interrompue !"
      exit 1
    fi
  fi

  # detect distro
  detect_distro

  print_brake 70
  echo "* Script d'installation de Pterodactyl Wings @ $SCRIPT_RELEASE"
  echo "*"
  echo "* Copyright (C) 2020 - 2022, Arno"
  echo "*"
  echo "* Ce script n'est pas associé au projet officiel Pterodactyl."
  echo "*"
  echo "* En cours d'éxecution sur $OS version $OS_VER."
  echo "* La dernière version de wings est $WINGS_VERSION"
  print_brake 70

  # checks if the system is compatible with this installation script
  check_os_comp

  echo "* "
  echo "* Le programme d'installation va installer Docker, les dépendances requises pour Wings"
  echo "* ainsi que Wings lui-même. Mais il est toujours nécessaire de créer une node"
  echo "* Vous pouvez soit copier manuellement le fichier de configuration depuis le panel vers /etc/pterodactyl/config.yml"
  echo "* ou, vous pouvez utiliser le \"auto deploy\" du panneau et collez simplement la commande dans ce terminal"
  echo "* l'installation est terminée. Pour en savoir plus sur ce processus, consultez le site"
  echo "* La documentation officielle : $(hyperlink 'https://pterodactyl.io/wings/1.0/installing.html#configure')"
  echo "* "
  echo -e "* ${COLOR_RED}Note${COLOR_NC}: ce script ne lancera pas Wings automatiquement (il installera le service systemd, mais ne le lancera pas)."
  echo -e "* ${COLOR_RED}Note${COLOR_NC}: ce script n'activera pas le swap (pour docker)."
  print_brake 42

  if [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
    echo -e -n "* Voulez-vous configurer automatiquement UFW & IPtables /!\ Recommandé /!\ ? (y/N) : "
    read -r CONFIRM_UFW

    if [[ "$CONFIRM_UFW" =~ [Yy] ]]; then
      CONFIGURE_UFW=true
      CONFIGURE_FIREWALL=true
	  CONFIGURE_IPTABLES=true
	  
    fi
  fi

  if [ "$OS" == "centos" ]; then
    echo -e -n "* Voulez-vous configurer automatiquement firewall-cmd (pare-feu) ? (y/N): "
    read -r CONFIRM_FIREWALL_CMD

    if [[ "$CONFIRM_FIREWALL_CMD" =~ [Yy] ]]; then
      CONFIGURE_FIREWALL_CMD=true
      CONFIGURE_FIREWALL=true
    fi
  fi

  ask_database_user

  if [ "$CONFIGURE_DBHOST" == true ]; then
    type mysql >/dev/null 2>&1 && HAS_MYSQL=true || HAS_MYSQL=false

    if [ "$HAS_MYSQL" == false ]; then
      INSTALL_MARIADB=true
    fi

    MYSQL_DBHOST_USER="-"
    while [[ "$MYSQL_DBHOST_USER" == *"-"* ]]; do
      required_input MYSQL_DBHOST_USER "Database host username (pterodactyluser): " "" "pterodactyluser"
      [[ "$MYSQL_DBHOST_USER" == *"-"* ]] && print_error "Database user cannot contain hyphens"
    done

    password_input MYSQL_DBHOST_PASSWORD "Database host password: " "Password cannot be empty"
  fi

  ask_letsencrypt

  if [ "$CONFIGURE_LETSENCRYPT" == true ]; then
    while [ -z "$FQDN" ]; do
      echo -n "* Définissez le nom de domaine à utiliser pour Let's Encrypt (node.zkillu.fr) : "
      read -r FQDN

      ASK=false

      [ -z "$FQDN" ] && print_error "FQDN cannot be empty"                                                            # check if FQDN is empty
      bash <(curl -s $GITHUB_BASE_URL/lib/verify-fqdn.sh) "$FQDN" "$OS" || ASK=true                                   # check if FQDN is valid
      [ -d "/etc/letsencrypt/live/$FQDN/" ] && print_error "A certificate with this FQDN already exists!" && ASK=true # check if cert exists

      [ "$ASK" == true ] && FQDN=""
      [ "$ASK" == true ] && echo -e -n "* Voulez-vous toujours configurer automatiquement HTTPS en utilisant Let's Encrypt ? (y/N) : "
      [ "$ASK" == true ] && read -r CONFIRM_SSL

      if [[ ! "$CONFIRM_SSL" =~ [Yy] ]] && [ "$ASK" == true ]; then
        CONFIGURE_LETSENCRYPT=false
        FQDN="none"
      fi
    done
  fi

  if [ "$CONFIGURE_LETSENCRYPT" == true ]; then
    # set EMAIL
    while ! valid_email "$EMAIL"; do
      echo -n "* Entrez l'Email pour Let's Encrypt : "
      read -r EMAIL

      valid_email "$EMAIL" || print_error "L'adresse électronique ne peut pas être vide ou invalide"
    done
  fi

  echo -n "* Procéder à l'installation ? (y/N) : "

  read -r CONFIRM
  [[ "$CONFIRM" =~ [Yy] ]] && perform_install && return

  print_error "Installation interrompue"
  exit 0
}

function goodbye {
  echo ""
  print_brake 70
  echo "* L'installation des wings vient de se terminer"
  echo "*"
  echo "* Pour continuer, vous devez configurer Wings pour qu'il fonctionne avec votre panel."
  echo "* Veuillez vous référer au guide officiel, $(hyperlink 'https://pterodactyl.io/wings/1.0/installing.html#configure')"
  echo "* "
  echo "* Vous pouvez soit copier manuellement le fichier de configuration depuis le panel vers /etc/pterodactyl/config.yml"
  echo "* ou, vous pouvez utiliser le \"auto deploy\" du panneau et collez simplement la commande dans ce terminal"
  echo "* "
  echo "* Vous pouvez ensuite lancer Wings manuellement pour vérifier qu'il fonctionne."
  echo "*"
  echo "* sudo wings"
  echo "*"
  echo "* Une fois que vous avez vérifié qu'il fonctionne, utilisez CTRL+C et démarrez Wings en tant que service (fonctionne en arrière-plan)."
  echo "*"
  echo "* systemctl start wings"
  echo "*"
  echo -e "* ${COLOR_RED}Note${COLOR_NC}: Il est recommandé d'activer le swap (pour Docker, lire la documentation officielle)."
  [ "$CONFIGURE_FIREWALL" == false ] && echo -e "* ${COLOR_RED}Note${COLOR_NC}: Si vous n'avez pas configuré votre pare-feu, les ports 8080 et 2022 doivent être ouverts."
  print_brake 70
  echo ""
}

# run script
main
goodbye
