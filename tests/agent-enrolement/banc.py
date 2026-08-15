#!/usr/bin/env python3
# =============================================================================
# Le banc de l'agent d'enrôlement — tout ce qui n'est pas un cas de test.
#
# Il monte quatre choses et les démonte proprement :
#
#   1. LE MOCK du plan de contrôle (`smartbureau-server/contrats/mock/`),
#      sur sa **surface proxy** : `POST /enroler` et `GET /config-kit`, et
#      rien d'autre. C'est ce que voit un kit (annexe 2 §7) — développer
#      contre la surface plan-machine laisserait passer un kit qui appelle
#      `/peers`. Le pilotage `/_mock/`, lui, n'existe QUE sur la surface
#      plan-machine : le banc s'en sert, le kit ne le voit jamais.
#
#   2. UN SCÉNARIO DÉRIVÉ de `scenario-exemple.json` — copié, jamais modifié
#      en place (README du mock §3). Une seule valeur change : l'IP publique
#      de `gw1` devient `127.0.0.1`, pour que l'IP de repli servie dans
#      `repoll` mène au mock. Conséquence voulue : **tout re-poll du banc
#      emprunte le chemin de repli** de l'arbitrage Q3 (nom qui ne résout
#      pas → `--resolve`, nom conservé), qui est le chemin le moins évident
#      et le plus facile à casser.
#
#   3. UN RÉSOLVEUR DU BANC : le chemin de repli de l'arbitrage Q3 ne se
#      déclenche que sur un échec de RÉSOLUTION (curl 6) — il faut donc que
#      le nom `gw-01.gateway.smartbureau.example` échoue VITE. Confier cet
#      échec au DNS de la machine est une dépendance extérieure cachée : sur
#      un lien lent (constaté sur le Pi de labo, 4G), une réponse NXDOMAIN
#      qui dépasse AGENT_DELAI_HTTP_S fait sortir curl en 28, le tour est
#      perdu, et le banc flotte — jamais sur le même cas. Le banc répond
#      donc lui-même NXDOMAIN (127.88.99.53:53, en microsecondes), et
#      l'agent d'enrôlement tourne dans un mount-namespace privé où
#      `/etc/resolv.conf` pointe dessus. Rien ne sort de la machine, rien
#      n'est modifié sur l'hôte. (`localhost`, lui, se résout par
#      `/etc/hosts` — la voie « nom qui résout » d'A-13 n'est pas touchée.)
#
#   4. DES DOUBLURES pour `wg`, `wg-quick` et `ip`, en tête de `PATH`. Le
#      banc recette la MACHINE À ÉTATS et les ÉCRITURES D'ÉTAT, pas la
#      cryptographie de WireGuard : les interfaces sont l'affaire de
#      `tests/roles/` (qui exige, lui, sudo et le module noyau). Les
#      doublures JOURNALISENT leurs appels — c'est ainsi qu'on vérifie
#      qu'une clé privée n'est générée qu'une fois, et qu'une rotation
#      passe par `wg syncconf` et jamais par un `wg-quick down`.
#
# Aucune dépendance : bibliothèque standard, `curl`, `jq`, `sh`. Ni Docker
# ni module noyau — c'est ce qui rend la tranche 2 recettable là où
# `tests/roles/` se déclare sauté. (Le résolveur du banc souhaite le port
# 53 sur la boucle locale — root, que les cas exigent déjà — et se dégrade
# proprement sans lui : comportement d'avant, exact mais flottant.)
# =============================================================================

import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

RACINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AGENT = os.path.join(RACINE, "docker", "wg", "agent-enrolement.sh")

# GID figé (annexe 2, invariant 3) — le banc le vérifie, il ne le choisit pas.
GID_LECTURE = 3000


def corpus():
    """Le dépôt `smartbureau-server`, domicile du corpus ET du mock."""
    chemin = os.environ.get("SMARTBUREAU_SERVER")
    if chemin:
        return chemin
    voisin = os.path.join(os.path.dirname(RACINE), "smartbureau-server")
    return voisin if os.path.isdir(voisin) else None


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


DOUBLURE_WG = """#!/bin/sh
# Doublure de `wg` — journalise, puis répond le minimum utile.
echo "wg $*" >> "$BANC_JOURNAL"
case "$1" in
  genkey)
    n=$(cat "$BANC_COMPTEUR" 2>/dev/null || echo 0); n=$((n + 1))
    echo "$n" > "$BANC_COMPTEUR"
    # Une clé DIFFÉRENTE à chaque appel : c'est ce qui rend visible une
    # régénération intempestive (l'idempotence du rejeu en dépend).
    printf 'cle-privee-de-recette-%s\\n' "$n" ;;
  pubkey)
    lu=$(cat); printf 'publique-de-%s\\n' "$lu" ;;
  *) exit 0 ;;
esac
"""

DOUBLURE_WG_QUICK = """#!/bin/sh
echo "wg-quick $*" >> "$BANC_JOURNAL"
case "$1" in
  strip) cat "$2" ;;
  *) exit 0 ;;
esac
"""

DOUBLURE_IP = """#!/bin/sh
# wg0 n'est « montée » que si le banc a posé le marqueur.
case "$*" in
  "link show wg0") [ -f "$BANC_WG0_MONTEE" ] || exit 1 ;;
esac
exit 0
"""

# `mv` est le geste qui PUBLIE un fichier d'état (`poser`). Le faire échouer
# sur un fichier désigné est le seul moyen d'observer l'ORDRE des écritures
# : une séquence interrompue au milieu doit laisser `usine.json` en place.
DOUBLURE_MV = """#!/bin/sh
if [ -n "${BANC_MV_ECHOUE:-}" ]; then
  for destination in "$@"; do :; done
  case "${destination##*/}" in
    "$BANC_MV_ECHOUE") echo "mv: échec simulé par le banc" >&2; exit 1 ;;
  esac
fi
exec %(mv)s "$@"
"""


class Banc:
    def __init__(self):
        self.racine = tempfile.mkdtemp(prefix="banc-agent-")
        self.doublures = os.path.join(self.racine, "doublures")
        os.makedirs(self.doublures)
        for nom, contenu in (("wg", DOUBLURE_WG), ("wg-quick", DOUBLURE_WG_QUICK),
                             ("ip", DOUBLURE_IP),
                             ("mv", DOUBLURE_MV % {"mv": shutil.which("mv") or "/bin/mv"})):
            chemin = os.path.join(self.doublures, nom)
            with open(chemin, "w") as f:
                f.write(contenu)
            os.chmod(chemin, 0o755)
        self.port_machine = port_libre()
        self.port_proxy = port_libre()
        self.processus = None
        self.trace = os.path.join(self.racine, "mock.trace")
        self.tls_arret = None
        self.tls_ecoute = None
        self.tls_ca = None
        self.tls_ca_etrangere = None
        self.resolveur_ecoute = None
        self.resolv_conf = None
        self.demarrer_resolveur()

    # --- Le résolveur du banc ----------------------------------------------

    def demarrer_resolveur(self):
        """NXDOMAIN immédiat, pour que le repli Q3 ne dépende d'aucun DNS réel.

        Port 53 sur une adresse de la boucle locale (tout 127/8 écoute sans
        rien configurer) : il faut être root — ce que les cas exigent déjà.
        Sans root, on laisse le DNS de la machine faire (comportement
        d'avant, exact mais flottant sur lien lent).
        """
        try:
            ecoute = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ecoute.bind(("127.88.99.53", 53))
        except OSError:
            return
        ecoute.settimeout(0.5)
        self.resolveur_ecoute = ecoute
        self.resolveur_arret = threading.Event()

        def repondre():
            while not self.resolveur_arret.is_set():
                try:
                    requete, origine = ecoute.recvfrom(512)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if len(requete) < 12:
                    continue
                # Réponse minimale : même identifiant, mêmes questions,
                # drapeaux QR|RD|RA, RCODE 3 (NXDOMAIN), zéro enregistrement.
                entete = requete[:2] + b"\x81\x83" + requete[4:6] + b"\x00\x00\x00\x00\x00\x00"
                try:
                    ecoute.sendto(entete + requete[12:], origine)
                except OSError:
                    pass

        threading.Thread(target=repondre, daemon=True).start()
        self.resolv_conf = os.path.join(self.racine, "resolv.conf")
        with open(self.resolv_conf, "w") as f:
            f.write("nameserver 127.88.99.53\noptions timeout:1 attempts:1\n")

    # --- Le mock ------------------------------------------------------------

    def scenario(self, source):
        """Copie du scénario d'exemple, avec `gw1` ramenée sur la boucle locale."""
        with open(os.path.join(source, "scenario-exemple.json")) as f:
            donnees = json.load(f)
        donnees["passerelles"][0]["ip_publique"] = "127.0.0.1"
        cible = os.path.join(self.racine, "scenario-banc.json")
        with open(cible, "w") as f:
            json.dump(donnees, f)
        return cible

    def demarrer_mock(self, source):
        """Le mock, BAVARD : sa trace de requêtes est un moyen d'observation.

        « Aucune requête n'est émise » (arbitrage Q6) ne se prouve pas côté
        kit — il faut regarder ce que le serveur a reçu.
        """
        self.journal_mock = open(self.trace, "w")
        self.processus = subprocess.Popen(
            [sys.executable, "mock.py", "--adresse", "127.0.0.1",
             "--port", str(self.port_machine), "--port-proxy", str(self.port_proxy),
             "--scenario", self.scenario(source)],
            cwd=source, stdout=self.journal_mock, stderr=subprocess.STDOUT)
        return self.attendre_mock()

    def joignable(self):
        """Les DEUX surfaces répondent-elles ?

        Le pilotage ne suffit pas : les écoutes se ferment et se rouvrent
        indépendamment, et c'est la surface proxy que l'agent d'enrôlement
        emploie. Sur le proxy, un `401` est une réponse — donc une écoute
        vivante.
        """
        try:
            self.pilotage("GET", "/_mock/sante")
        except Exception:
            return False
        try:
            urllib.request.urlopen(
                "http://127.0.0.1:%d/config-kit" % self.port_proxy, timeout=5).read()
        except urllib.error.HTTPError:
            return True
        except Exception:
            return False
        return True

    def attendre_mock(self, secondes=20):
        """Attend que le mock réponde de nouveau.

        Le mode de coupure `ecoute_fermee` ferme TOUTES les écoutes, pilotage
        compris — c'est le but, et elles se rouvrent seules. Le banc attend
        donc la réouverture au lieu de la supposer.
        """
        limite = time.time() + secondes
        while time.time() < limite:
            if self.joignable():
                return True
            time.sleep(0.1)
        return False

    def attendre_mock_ferme(self, secondes=10):
        """Attend que les écoutes soient EFFECTIVEMENT fermées.

        `fermer_puis_rouvrir` laisse d'abord partir la réponse de pilotage :
        la fermeture est différée de quelques dixièmes de seconde. Enchaîner
        sans attendre ferait courir l'agent d'enrôlement AVANT la coupure —
        un cas vert qui n'aurait rien coupé, et une fermeture qui
        retomberait au milieu du cas suivant.
        """
        limite = time.time() + secondes
        while time.time() < limite:
            if not self.joignable():
                return True
            time.sleep(0.1)
        return False

    def arreter(self):
        if self.resolveur_ecoute:
            self.resolveur_arret.set()
            try:
                self.resolveur_ecoute.close()
            except OSError:
                pass
        if self.tls_arret:
            self.tls_arret.set()
            try:
                self.tls_ecoute.close()
            except OSError:
                pass
        if self.processus:
            self.processus.send_signal(signal.SIGTERM)
            try:
                self.processus.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.processus.kill()
            self.journal_mock.close()
        shutil.rmtree(self.racine, ignore_errors=True)

    def pilotage(self, methode, chemin, corps=None, entetes=None):
        """Surface `/_mock/` et API d'administration — jamais vues d'un kit."""
        url = "http://127.0.0.1:%d%s" % (self.port_machine, chemin)
        donnees = json.dumps(corps).encode() if corps is not None else None
        requete = urllib.request.Request(url, data=donnees, method=methode)
        requete.add_header("Content-Type", "application/json")
        for cle, valeur in (entetes or {}).items():
            requete.add_header(cle, valeur)
        with urllib.request.urlopen(requete, timeout=10) as reponse:
            brut = reponse.read()
            return json.loads(brut) if brut else {}

    def admin(self, methode, chemin, corps=None):
        jeton = "jeton-admin-de-developpement"
        return self.pilotage(methode, chemin, corps,
                             {"Authorization": "Bearer " + jeton})

    def reinitialiser(self):
        self.pilotage("POST", "/_mock/coupure/effacer", {})
        self.pilotage("POST", "/_mock/reinitialiser", {})

    # --- Observation de ce que le serveur a reçu ----------------------------

    def marque_trace(self):
        self.journal_mock.flush()
        return os.path.getsize(self.trace)

    def requetes_depuis(self, marque, motif):
        self.journal_mock.flush()
        with open(self.trace, errors="replace") as f:
            f.seek(marque)
            return [l for l in f.read().splitlines() if motif in l and "->" in l]

    # --- TLS : la seule façon de prouver l'arbitrage Q3 --------------------
    #
    # Le mock parle en clair (c'est assumé : la terminaison TLS appartient au
    # proxy d'enrôlement, jamais à l'application). Or Q3 porte précisément
    # sur ce que le repli fait de TLS — SNI, chaîne, nom conservé. Le banc
    # pose donc devant le mock une terminaison TLS avec un certificat au nom
    # `gw-01.gateway.smartbureau.example`, signé par une CA de banc.
    #
    # Ce que ce montage rend OBSERVABLE : si l'agent d'enrôlement joignait
    # l'IP en réécrivant l'URL au lieu d'employer `--resolve`, le certificat
    # ne correspondrait plus (aucun SAN sur l'IP) et l'appel échouerait. Et
    # s'il désactivait la vérification, l'essai à la CA ÉTRANGÈRE réussirait
    # au lieu d'échouer. Les deux mutations sont donc rouges.

    def certificats(self):
        """CA de banc + certificat du nom `gw-01…`, et une CA étrangère."""
        rep = os.path.join(self.racine, "tls")
        os.makedirs(rep, exist_ok=True)
        nom = "gw-01.gateway.smartbureau.example"
        extension = os.path.join(rep, "ext.cnf")
        with open(extension, "w") as f:
            f.write("subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n" % nom)

        def ouvrir(*args):
            subprocess.run(args, cwd=rep, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for prefixe, sujet in (("ca", "/CN=CA du banc agent-enrolement"),
                               ("etrangere", "/CN=CA etrangere du banc")):
            ouvrir("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                   "-keyout", prefixe + ".key", "-out", prefixe + ".pem",
                   "-days", "1", "-subj", sujet)
        ouvrir("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
               "-keyout", "serveur.key", "-out", "serveur.csr", "-subj", "/CN=" + nom)
        ouvrir("openssl", "x509", "-req", "-in", "serveur.csr",
               "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
               "-out", "serveur.pem", "-days", "1", "-extfile", "ext.cnf")
        return (os.path.join(rep, "ca.pem"), os.path.join(rep, "etrangere.pem"),
                os.path.join(rep, "serveur.pem"), os.path.join(rep, "serveur.key"))

    def demarrer_tls(self):
        """Terminaison TLS devant la surface proxy. Rend le port, ou None."""
        if not shutil.which("openssl"):
            return None
        try:
            ca, etrangere, cert, cle = self.certificats()
        except (subprocess.CalledProcessError, OSError):
            return None
        contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        contexte.load_cert_chain(cert, cle)
        ecoute = socket.socket()
        ecoute.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ecoute.bind(("127.0.0.1", 0))
        ecoute.listen(16)
        ecoute.settimeout(0.5)
        self.tls_ecoute = ecoute
        self.tls_ca, self.tls_ca_etrangere = ca, etrangere
        self.tls_arret = threading.Event()

        def pomper(source, destination):
            try:
                while True:
                    bloc = source.recv(65536)
                    if not bloc:
                        break
                    destination.sendall(bloc)
            except OSError:
                pass
            finally:
                for s in (source, destination):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        def servir(brut):
            try:
                chiffre = contexte.wrap_socket(brut, server_side=True)
            except (ssl.SSLError, OSError):
                brut.close()
                return
            try:
                amont = socket.create_connection(("127.0.0.1", self.port_proxy))
            except OSError:
                chiffre.close()
                return
            threading.Thread(target=pomper, args=(chiffre, amont), daemon=True).start()
            pomper(amont, chiffre)

        def boucle():
            while not self.tls_arret.is_set():
                try:
                    brut, _ = ecoute.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=servir, args=(brut,), daemon=True).start()

        self.tls_fil = threading.Thread(target=boucle, daemon=True)
        self.tls_fil.start()
        return ecoute.getsockname()[1]

    # --- Le bac à sable d'un cas -------------------------------------------

    def sable(self, nom):
        base = os.path.join(self.racine, nom)
        controle = os.path.join(base, "controle")
        conf = os.path.join(base, "wireguard")
        os.makedirs(controle, exist_ok=True)
        os.makedirs(conf, exist_ok=True)
        return base, controle, conf

    def poser_usine(self, controle, hote="gw-01.gateway.smartbureau.example",
                    secret="secret-usine-A0001-de-developpement", resoluble=False,
                    tls=None):
        """Le fichier d'usine, à son domicile d'USAGE (arbitrage Q2).

        `controle/usine.json` en `600 root` : c'est `premier-demarrage` qui
        l'a déplacé depuis `/boot` (annexe 2 §2.2 étape 3). Le banc joue
        donc l'état du kit APRÈS le premier démarrage, ce qui est
        exactement ce que l'agent d'enrôlement trouve.
        """
        nom = "localhost" if resoluble else hote
        schema, port = ("https", tls) if tls else ("http", self.port_proxy)
        usine = {
            "kit_id": "A0001",
            "secret": secret,
            "enrolement": ["%s://%s:%d/enroler" % (schema, nom, port)],
            "repli": [{"hote": nom, "ip": "127.0.0.1"}],
            "empreinte_tls": "sha256/RmF1eEVtcHJlaW50ZURlRGV2ZWxvcHBlbWVudEFBQUE=",
            "local": {"wifi_psk": "psk-de-developpement"},
            "emis_le": "2026-08-06", "lot": "F-2026-031",
        }
        chemin = os.path.join(controle, "usine.json")
        with open(chemin, "w") as f:
            json.dump(usine, f)
        os.chmod(chemin, 0o600)
        return chemin

    # --- L'agent d'enrôlement ----------------------------------------------

    def agent(self, base, controle, conf, tours=1, nominale=0, suspendu=0,
              backoff=0, timeout=120, mv_echoue=None, tls=None, ca=None):
        """Lance l'agent d'enrôlement tel qu'il tourne sur le kit : `sh`, root, curl, jq.

        Les cadences du corpus (6 h / 24 h / 1→15 min) sont surchargées :
        une recette qui les respecterait durerait une journée. Leurs valeurs
        par défaut sont vérifiées à part (cas A-16).
        """
        environnement = {
            k: v for k, v in os.environ.items()
            if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
        }
        environnement.update({
            "PATH": self.doublures + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "no_proxy": "*",
            "WG_ROLE": "kit",
            "CONTROLE": controle,
            "WG_CONF": conf,
            "AGENT_TOURS": str(tours),
            "AGENT_PERIODE_NOMINALE_S": str(nominale),
            "AGENT_PERIODE_SUSPENDU_S": str(suspendu),
            "AGENT_BACKOFF_MIN_S": str(backoff),
            "AGENT_BACKOFF_MAX_S": str(backoff),
            "AGENT_DELAI_HTTP_S": "5",
            "AGENT_REPOLL_SCHEMA": "http",
            "AGENT_REPOLL_PORT": str(self.port_proxy),
            "BANC_JOURNAL": os.path.join(base, "appels-wg.txt"),
            "BANC_COMPTEUR": os.path.join(base, "compteur-genkey"),
            "BANC_WG0_MONTEE": os.path.join(base, "wg0-montee"),
        })
        if mv_echoue:
            environnement["BANC_MV_ECHOUE"] = mv_echoue
        if tls:
            # Le re-poll parle alors HTTPS à la terminaison TLS du banc, avec
            # la seule ancre que le banc lui donne (`CURL_CA_BUNDLE` tient ici
            # la place du magasin système de l'image).
            environnement["AGENT_REPOLL_SCHEMA"] = "https"
            environnement["AGENT_REPOLL_PORT"] = str(tls)
        if ca:
            environnement["CURL_CA_BUNDLE"] = ca
        commande = ["sh", AGENT]
        resolv_a_restaurer = None
        if self.resolv_conf and self._unshare_mount_utilisable():
            # Mount-namespace privé (propagation coupée par défaut) : le
            # resolv.conf du banc n'est visible que de l'agent d'enrôlement,
            # l'hôte n'est jamais touché. `mount` suit le lien symbolique
            # qu'est /etc/resolv.conf sur la plupart des hôtes.
            commande = ["unshare", "--mount", "sh", "-c",
                        'mount --bind "$BANC_RESOLV" /etc/resolv.conf && exec sh "$0"',
                        AGENT]
            environnement["BANC_RESOLV"] = self.resolv_conf
        elif self.resolv_conf and os.environ.get("BANC_RESOLV_DIRECT") == "1":
            # Repli de CI, sur opt-in EXPLICITE : dans le conteneur de tâche,
            # CLONE_NEWNS est refusé (seccomp, capacités), mais /etc/resolv.conf
            # n'appartient qu'au conteneur jetable — écriture directe,
            # restaurée aussitôt l'agent d'enrôlement rendu. Jamais par
            # défaut : sur un poste, l'hôte ne se touche pas.
            with open("/etc/resolv.conf") as f:
                resolv_a_restaurer = f.read()
            shutil.copyfile(self.resolv_conf, "/etc/resolv.conf")
        debut = time.time()
        try:
            acheve = subprocess.run(commande, env=environnement, timeout=timeout,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        finally:
            if resolv_a_restaurer is not None:
                with open("/etc/resolv.conf", "w") as f:
                    f.write(resolv_a_restaurer)
        return acheve, time.time() - debut

    _unshare_mount = None

    @classmethod
    def _unshare_mount_utilisable(cls):
        """La présence d'`unshare` ne prouve rien : dans un conteneur, le
        noyau refuse CLONE_NEWNS à l'exécution (constaté sur l'exécuteur de
        CI). Sonder une fois, pas supposer."""
        if cls._unshare_mount is None:
            try:
                cls._unshare_mount = bool(shutil.which("unshare")) and \
                    subprocess.run(["unshare", "--mount", "true"],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL).returncode == 0
            except OSError:
                cls._unshare_mount = False
        return cls._unshare_mount

    @staticmethod
    def appels_wg(base):
        chemin = os.path.join(base, "appels-wg.txt")
        if not os.path.exists(chemin):
            return []
        with open(chemin) as f:
            return f.read().splitlines()


# --- Petites lectures d'état, partagées par les cas -------------------------

def mode(chemin):
    return oct(os.stat(chemin).st_mode & 0o777)[2:]


def proprietaire(chemin):
    infos = os.stat(chemin)
    return infos.st_uid, infos.st_gid


def lire(chemin):
    with open(chemin) as f:
        return f.read()


def lire_json(chemin):
    with open(chemin) as f:
        return json.load(f)


def empreintes(repertoire):
    """(taille, mtime_ns) de chaque fichier — pour prouver qu'un 304 ne touche rien."""
    releve = {}
    for racine, _, fichiers in os.walk(repertoire):
        for nom in fichiers:
            chemin = os.path.join(racine, nom)
            infos = os.stat(chemin)
            releve[os.path.relpath(chemin, repertoire)] = (infos.st_size, infos.st_mtime_ns)
    return releve
