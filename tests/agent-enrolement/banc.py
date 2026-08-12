#!/usr/bin/env python3
# =============================================================================
# Le banc de l'agent d'enrôlement — tout ce qui n'est pas un cas de test.
#
# Il monte trois choses et les démonte proprement :
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
#   3. DES DOUBLURES pour `wg`, `wg-quick` et `ip`, en tête de `PATH`. Le
#      banc recette la MACHINE À ÉTATS et les ÉCRITURES D'ÉTAT, pas la
#      cryptographie de WireGuard : les interfaces sont l'affaire de
#      `tests/roles/` (qui exige, lui, sudo et le module noyau). Les
#      doublures JOURNALISENT leurs appels — c'est ainsi qu'on vérifie
#      qu'une clé privée n'est générée qu'une fois, et qu'une rotation
#      passe par `wg syncconf` et jamais par un `wg-quick down`.
#
# Aucune dépendance : bibliothèque standard, `curl`, `jq`, `sh`. Ni Docker
# ni privilège réseau — c'est ce qui rend la tranche 2 recettable là où
# `tests/roles/` se déclare sauté.
# =============================================================================

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
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


class Banc:
    def __init__(self):
        self.racine = tempfile.mkdtemp(prefix="banc-agent-")
        self.doublures = os.path.join(self.racine, "doublures")
        os.makedirs(self.doublures)
        for nom, contenu in (("wg", DOUBLURE_WG), ("wg-quick", DOUBLURE_WG_QUICK),
                             ("ip", DOUBLURE_IP)):
            chemin = os.path.join(self.doublures, nom)
            with open(chemin, "w") as f:
                f.write(contenu)
            os.chmod(chemin, 0o755)
        self.port_machine = port_libre()
        self.port_proxy = port_libre()
        self.processus = None
        self.trace = os.path.join(self.racine, "mock.trace")

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

    def attendre_mock(self, secondes=20):
        """Attend que le mock réponde.

        Le mode de coupure `ecoute_fermee` ferme TOUTES les écoutes, pilotage
        compris — c'est le but, et elles se rouvrent seules. Le banc attend
        donc la réouverture au lieu de la supposer.
        """
        limite = time.time() + secondes
        while time.time() < limite:
            try:
                self.pilotage("GET", "/_mock/sante")
                return True
            except Exception:
                time.sleep(0.1)
        return False

    def arreter(self):
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

    # --- Le bac à sable d'un cas -------------------------------------------

    def sable(self, nom):
        base = os.path.join(self.racine, nom)
        controle = os.path.join(base, "controle")
        conf = os.path.join(base, "wireguard")
        os.makedirs(controle, exist_ok=True)
        os.makedirs(conf, exist_ok=True)
        return base, controle, conf

    def poser_usine(self, controle, hote="gw-01.gateway.smartbureau.example",
                    secret="secret-usine-A0001-de-developpement", resoluble=False):
        """Le fichier d'usine, à son domicile d'USAGE (arbitrage Q2).

        `controle/usine.json` en `600 root` : c'est `premier-demarrage` qui
        l'a déplacé depuis `/boot` (annexe 2 §2.2 étape 3). Le banc joue
        donc l'état du kit APRÈS le premier démarrage, ce qui est
        exactement ce que l'agent d'enrôlement trouve.
        """
        nom = "localhost" if resoluble else hote
        usine = {
            "kit_id": "A0001",
            "secret": secret,
            "enrolement": ["http://%s:%d/enroler" % (nom, self.port_proxy)],
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
              backoff=0, timeout=120):
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
        debut = time.time()
        acheve = subprocess.run(["sh", AGENT], env=environnement, timeout=timeout,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return acheve, time.time() - debut

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
