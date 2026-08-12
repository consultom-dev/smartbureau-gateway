#!/usr/bin/env python3
# =============================================================================
# Cas W-01 … W-11 — le watchdog de bascule et la boucle de marqueurs
# (critère de fini 3 du lot 2, plan §4 : « passerelle simulée muette →
# bascule d'endpoint ≤ 60 s ; l'agent d'enrôlement tué → la bascule
# fonctionne encore »).
#
# Fait foi : **annexe 2 §3.4** (le watchdog), **§3.2** (l'état local et ses
# propriétaires), arch. §6.2 et §7 ; arbitrages N4 (le port dans un fichier)
# et Q7 (la clé du peer vient de `wg show`).
#
# Ni Docker, ni module noyau, ni réseau : `wg`, `ping` et `ip` sont des
# doublures. Celle de `wg` porte un ÉTAT — un peer, un endpoint, un
# handshake — que `wg set` modifie : c'est ce qui permet de vérifier une
# bascule au lieu de vérifier qu'une commande a été appelée.
#
#   Usage :  ./tests/watchdog/lancer.py
# =============================================================================

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(os.path.dirname(ICI))
sys.path.insert(0, os.path.dirname(ICI))

from tap import Recette, sortir                                   # noqa: E402

WATCHDOG = os.path.join(RACINE, "docker", "wg", "watchdog.sh")
MARQUEURS = os.path.join(RACINE, "docker", "wg", "marqueurs.sh")

r = Recette(lot=2)

# --- Les doublures ----------------------------------------------------------

DOUBLURE_WG = """#!/bin/sh
echo "wg $*" >> "$BANC_JOURNAL"
case "$1" in
  show)
    cle=$(cat "$BANC_PEER" 2>/dev/null)
    [ -n "$cle" ] || exit 0
    case "$3" in
      peers)             printf '%s\\n' "$cle" ;;
      endpoints)         printf '%s\\t%s\\n' "$cle" "$(cat "$BANC_ENDPOINT" 2>/dev/null)" ;;
      latest-handshakes) printf '%s\\t%s\\n' "$cle" "$(cat "$BANC_HANDSHAKE" 2>/dev/null)" ;;
    esac ;;
  set)
    # wg set <iface> peer <cle> endpoint <ip:port>
    [ "$5" = "endpoint" ] || exit 1
    printf '%s\\n' "$6" > "$BANC_ENDPOINT"
    printf '%s\\n' "$4" > "$BANC_PEER_POSE" ;;
esac
exit 0
"""

DOUBLURE_PING = """#!/bin/sh
echo "ping $*" >> "$BANC_JOURNAL"
[ -f "$BANC_MUET" ] && exit 1
exit 0
"""

DOUBLURE_IP = """#!/bin/sh
case "$*" in
  "link show wg0") [ -f "$BANC_WG0" ] || exit 1 ;;
esac
exit 0
"""


class Banc:
    def __init__(self):
        self.racine = tempfile.mkdtemp(prefix="banc-watchdog-")
        self.doublures = os.path.join(self.racine, "doublures")
        os.makedirs(self.doublures)
        for nom, contenu in (("wg", DOUBLURE_WG), ("ping", DOUBLURE_PING),
                             ("ip", DOUBLURE_IP)):
            chemin = os.path.join(self.doublures, nom)
            with open(chemin, "w") as f:
                f.write(contenu)
            os.chmod(chemin, 0o755)

    def sable(self, nom, endpoints=("203.0.113.10", "198.51.100.7", "192.0.2.30"),
              port="51820", peer="CLE-PARTAGEE-DES-PASSERELLES=",
              endpoint_courant="203.0.113.10:51820", wg0=True, muet=False):
        base = os.path.join(self.racine, nom)
        controle = os.path.join(base, "controle")
        os.makedirs(controle, exist_ok=True)
        if endpoints is not None:
            with open(os.path.join(controle, "endpoints.txt"), "w") as f:
                f.write("".join(ip + "\n" for ip in endpoints))
        if port is not None:
            with open(os.path.join(controle, "port"), "w") as f:
                f.write(port + "\n")
        self.ecrire(base, "peer", peer)
        self.ecrire(base, "endpoint", endpoint_courant)
        self.ecrire(base, "handshake", "1754476301")
        if wg0:
            open(os.path.join(base, "wg0"), "w").close()
        if muet:
            open(os.path.join(base, "muet"), "w").close()
        return base, controle

    @staticmethod
    def ecrire(base, nom, valeur):
        with open(os.path.join(base, nom), "w") as f:
            f.write(valeur + "\n")

    @staticmethod
    def lire(base, nom):
        chemin = os.path.join(base, nom)
        if not os.path.exists(chemin):
            return ""
        with open(chemin) as f:
            return f.read().strip()

    def environnement(self, base, controle):
        env = dict(os.environ)
        env.update({
            "PATH": self.doublures + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "WG_ROLE": "kit",
            "CONTROLE": controle,
            "BANC_JOURNAL": os.path.join(base, "appels.txt"),
            "BANC_PEER": os.path.join(base, "peer"),
            "BANC_PEER_POSE": os.path.join(base, "peer-pose"),
            "BANC_ENDPOINT": os.path.join(base, "endpoint"),
            "BANC_HANDSHAKE": os.path.join(base, "handshake"),
            "BANC_WG0": os.path.join(base, "wg0"),
            "BANC_MUET": os.path.join(base, "muet"),
        })
        return env

    def watchdog(self, base, controle, tours=1, periode=0, timeout=60):
        env = self.environnement(base, controle)
        env.update({"WATCHDOG_TOURS": str(tours), "WATCHDOG_PERIODE_S": str(periode)})
        debut = time.time()
        acheve = subprocess.run(["sh", WATCHDOG], env=env, timeout=timeout,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return acheve, time.time() - debut

    def marqueurs(self, base, controle, tours=1, periode=0, timeout=60):
        env = self.environnement(base, controle)
        env.update({"MARQUEURS_TOURS": str(tours), "MARQUEURS_PERIODE_S": str(periode)})
        return subprocess.run(["sh", MARQUEURS], env=env, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    @staticmethod
    def appels(base):
        chemin = os.path.join(base, "appels.txt")
        if not os.path.exists(chemin):
            return []
        with open(chemin) as f:
            return f.read().splitlines()

    def arreter(self):
        shutil.rmtree(self.racine, ignore_errors=True)


def prerequis():
    if not os.path.isfile(WATCHDOG):
        return "docker/wg/watchdog.sh absent"
    for outil in ("sh", "jq", "awk"):
        if not shutil.which(outil):
            return "%s absent" % outil
    return None


MOTIF = prerequis()
if MOTIF:
    for nom in ["W-01 chemin sain", "W-02 bascule", "W-03 rotation circulaire",
                "W-04 port relu", "W-05 clé du peer", "W-06 bascule ≤ 60 s",
                "W-07 agent d'enrôlement mort", "W-08 liste absente",
                "W-09 interface absente", "W-10 marqueurs", "W-11 marqueurs prudents"]:
        r.cas(nom, "annexe 2 §3.4")
        r.sauter(nom, MOTIF)
    sortir(r)

banc = Banc()
lire_source = open(WATCHDOG).read()

try:
    # =========================================================================
    r.cas("W-01 — le chemin complet répond : le watchdog ne touche à RIEN",
          "annexe 2 §3.4 ; arch. §6.2")
    base, controle = banc.sable("w01")
    banc.watchdog(base, controle, tours=3)
    r.verifier(banc.lire(base, "endpoint") == "203.0.113.10:51820",
               "endpoint inchangé", banc.lire(base, "endpoint"))
    r.verifier(not any(a.startswith("wg set") for a in banc.appels(base)),
               "aucun `wg set` — un tunnel sain ne se reconfigure pas",
               banc.appels(base))
    r.verifier(sum(1 for a in banc.appels(base) if a.startswith("ping")) == 3,
               "un ping par battement, et c'est tout")
    r.verifier("-c3 -W2 10.100.0.1" in " ".join(banc.appels(base)),
               "le ping vise 10.100.0.1 — le SERVEUR, donc le chemin complet, "
               "pas le handshake de la passerelle", banc.appels(base))
    r.fin("W-01 chemin sain")

    # =========================================================================
    r.cas("W-02 — passerelle muette : bascule sur l'endpoint SUIVANT",
          "annexe 2 §3.4 ; arch. §7 ; plan §4 critère 3")
    base, controle = banc.sable("w02", muet=True)
    acheve, _ = banc.watchdog(base, controle, tours=1)
    r.verifier(banc.lire(base, "endpoint") == "198.51.100.7:51820",
               "l'endpoint a basculé vers le suivant de la liste",
               banc.lire(base, "endpoint") + " — " + acheve.stderr.decode()[-200:])
    r.verifier(banc.lire(base, "peer-pose") == "CLE-PARTAGEE-DES-PASSERELLES=",
               "et la commutation porte sur le peer de l'interface")
    r.fin("W-02 bascule")

    # =========================================================================
    r.cas("W-03 — rotation CIRCULAIRE, et liste réécrite sous les pieds",
          "arch. §6.2 (ordre aléatoire fixé à l'enrôlement)")
    base, controle = banc.sable("w03", muet=True, endpoint_courant="192.0.2.30:51820")
    banc.watchdog(base, controle, tours=1)
    r.verifier(banc.lire(base, "endpoint") == "203.0.113.10:51820",
               "après le dernier, on revient au premier", banc.lire(base, "endpoint"))
    # L'agent d'enrôlement vient de réécrire la liste : l'endpoint courant
    # n'y figure plus. On repart de la tête plutôt que de ne rien faire.
    base, controle = banc.sable("w03bis", muet=True,
                                endpoint_courant="203.0.113.99:51820")
    banc.watchdog(base, controle, tours=1)
    r.verifier(banc.lire(base, "endpoint") == "203.0.113.10:51820",
               "endpoint courant absent de la liste → on repart de la tête",
               banc.lire(base, "endpoint"))
    r.fin("W-03 rotation circulaire")

    # =========================================================================
    r.cas("W-04 — le port est RELU à chaque commutation, jamais mémorisé",
          "annexe 2 §3.2 et §3.4 (arbitrage N4) ; arch. §11.4")
    base, controle = banc.sable("w04", muet=True)
    banc.watchdog(base, controle, tours=1)
    r.verifier(banc.lire(base, "endpoint").endswith(":51820"),
               "première bascule sur le port courant", banc.lire(base, "endpoint"))
    # Rotation de la clé partagée : la double écoute impose 51830 (§11.4).
    with open(os.path.join(controle, "port"), "w") as f:
        f.write("51830\n")
    banc.watchdog(base, controle, tours=1)
    r.verifier(banc.lire(base, "endpoint") == "192.0.2.30:51830",
               "la bascule suivante emploie 51830 — un watchdog qui mémorise "
               "le port rebascule sur l'ancien au pire moment",
               banc.lire(base, "endpoint"))
    r.fin("W-04 port relu")

    # =========================================================================
    r.cas("W-05 — la clé du peer vient de `wg show`, jamais d'une mémoire",
          "annexe 2 §3.4 (arbitrage Q7)")
    base, controle = banc.sable("w05", muet=True)
    banc.watchdog(base, controle, tours=1)
    # Rotation de la clé partagée : l'agent d'enrôlement réécrit le [Peer] et
    # resynchronise. Le watchdog, lui, n'a rien à apprendre — il relit.
    banc.ecrire(base, "peer", "NOUVELLE-CLE-APRES-ROTATION=")
    banc.watchdog(base, controle, tours=1)
    r.verifier(banc.lire(base, "peer-pose") == "NOUVELLE-CLE-APRES-ROTATION=",
               "la commutation emploie la clé COURANTE de l'interface",
               banc.lire(base, "peer-pose"))
    r.verifier("GW_PUBKEY" not in lire_source,
               "aucune clé de passerelle en variable d'environnement ni en dur")
    r.verifier("wg0.conf" not in lire_source,
               "et le watchdog ne lit pas non plus wg0.conf — deux fichiers, "
               "pas trois (invariant 5)")
    r.fin("W-05 clé du peer")

    # =========================================================================
    r.cas("W-06 — la bascule tient dans la première période : ≤ 60 s",
          "plan §4, critère de fini 3 ; annexe 2 §3.4")
    r.verifier("WATCHDOG_PERIODE_S:-30" in lire_source,
               "la période par défaut est 30 s (corpus)")
    r.verifier("ping -c3 -W2" in lire_source,
               "le ping est borné : -c3 -W2, soit 6 s au pire")
    base, controle = banc.sable("w06", muet=True)
    acheve, duree = banc.watchdog(base, controle, tours=1, periode=1)
    r.verifier(banc.lire(base, "endpoint") == "198.51.100.7:51820",
               "la bascule a lieu dès le PREMIER battement qui constate la panne "
               "— pas au suivant", banc.lire(base, "endpoint"))
    r.verifier(duree < 5,
               "et sans délai supplémentaire (30 s + 6 s au pire, soit < 60 s "
               "avec les valeurs du corpus)", "%.1fs" % duree)
    r.fin("W-06 bascule ≤ 60 s")

    # =========================================================================
    r.cas("W-07 — agent d'enrôlement mort : la bascule fonctionne quand même",
          "annexe 2, invariant 5 ; plan §4, critère de fini 3")
    base, controle = banc.sable("w07", muet=True)
    # On retire TOUT ce qui appartient à l'agent d'enrôlement : il n'y a
    # jamais eu de processus agent ici, et il n'en reste aucun fichier.
    for orphelin in ("usine.json", "secret_api", "etat-agent.json",
                     "repoll.txt", "endpoints.version"):
        chemin = os.path.join(controle, orphelin)
        if os.path.exists(chemin):
            os.remove(chemin)
    banc.watchdog(base, controle, tours=1)
    r.verifier(banc.lire(base, "endpoint") == "198.51.100.7:51820",
               "la bascule a eu lieu sans agent d'enrôlement ni aucun de ses fichiers",
               banc.lire(base, "endpoint"))
    r.verifier(sorted(os.listdir(controle)) == ["endpoints.txt", "port"],
               "le watchdog n'a lu — ni écrit — que ses DEUX fichiers",
               sorted(os.listdir(controle)))
    for interdit in ("secret_api", "usine.json", "curl", "etat.json"):
        r.verifier(interdit not in lire_source,
                   "le source ne mentionne pas %s" % interdit)
    r.fin("W-07 agent d'enrôlement mort")

    # =========================================================================
    r.cas("W-08 — liste d'endpoints absente ou vide : rien, mais pas de mort",
          "annexe 2 §3.4")
    base, controle = banc.sable("w08", muet=True, endpoints=None)
    acheve, _ = banc.watchdog(base, controle, tours=2)
    r.verifier(acheve.returncode == 0,
               "le watchdog survit à une liste absente", acheve.stderr.decode()[-200:])
    r.verifier(banc.lire(base, "endpoint") == "203.0.113.10:51820",
               "et ne commute pas au hasard")
    r.verifier("aucune bascule possible" in acheve.stderr.decode(),
               "il le dit, plutôt que d'échouer en silence")
    r.fin("W-08 liste absente")

    # =========================================================================
    r.cas("W-09 — interface absente au premier démarrage : ce n'est pas une panne",
          "annexe 2 §3.3 (l'enrôlement précède le tunnel)")
    base, controle = banc.sable("w09", muet=True, wg0=False)
    acheve, _ = banc.watchdog(base, controle, tours=2)
    r.verifier(acheve.returncode == 0, "le watchdog survit à l'absence de wg0")
    r.verifier(not any(a.startswith("ping") for a in banc.appels(base)),
               "il ne ping même pas : il n'y a pas encore de tunnel à surveiller",
               banc.appels(base))
    r.verifier(not any(a.startswith("wg set") for a in banc.appels(base)),
               "et ne commute rien")
    r.fin("W-09 interface absente")

    # =========================================================================
    r.cas("W-10 — la boucle de marqueurs publie etat.json, et elle seule",
          "annexe 2 §3.2 ; §4 (`sante`)")
    base, controle = banc.sable("w10")
    with open(os.path.join(controle, "etat-agent.json"), "w") as f:
        json.dump({"etat": "suspendu", "code_config_kit": "403",
                   "detail": "kit suspendu", "horodatage": "2026-08-12T00:00:00Z"}, f)
    banc.marqueurs(base, controle, tours=1)
    chemin = os.path.join(controle, "etat.json")
    if r.verifier(os.path.exists(chemin), "etat.json écrit"):
        etat = json.load(open(chemin))
        r.verifier(oct(os.stat(chemin).st_mode & 0o777)[2:] == "644",
                   "en 644 — `sante` le lit sans privilège (§3.2)")
        r.verifier(etat["etat"] == "suspendu" and etat["code_config_kit"] == "403",
                   "l'état et le dernier code sont RECOPIÉS d'etat-agent.json", etat)
        r.verifier(etat["endpoint"] == "203.0.113.10:51820",
                   "l'endpoint courant vient de `wg show`, pas d'un fichier", etat)
        r.verifier(etat["dernier_handshake"] == 1754476301,
                   "le dernier handshake aussi — c'est la vivacité du tunnel", etat)
    # Un seul propriétaire : le watchdog ne touche jamais etat.json.
    avant = os.stat(chemin).st_mtime_ns
    banc.watchdog(base, controle, tours=2)
    r.verifier(os.stat(chemin).st_mtime_ns == avant,
               "et le watchdog n'y touche jamais — un fichier atomique n'a "
               "qu'un propriétaire (§3.2)")
    r.fin("W-10 marqueurs")

    # =========================================================================
    r.cas("W-11 — les marqueurs n'inventent pas d'état",
          "annexe 2 §3.2 — « la fraîcheur vaut vie », pas la complaisance")
    base, controle = banc.sable("w11")
    banc.marqueurs(base, controle, tours=1)
    etat = json.load(open(os.path.join(controle, "etat.json")))
    r.verifier(etat["etat"] == "usine",
               "sans etat-agent.json, le kit est en usine — l'état de départ", etat)
    with open(os.path.join(controle, "etat-agent.json"), "w") as f:
        f.write("{ceci n'est pas du JSON")
    banc.marqueurs(base, controle, tours=1)
    etat = json.load(open(os.path.join(controle, "etat.json")))
    r.verifier(etat["etat"] == "inconnu",
               "etat-agent.json illisible → « inconnu », jamais un état plausible "
               "que `sante` remonterait comme une vérité", etat)
    base, controle = banc.sable("w11bis", wg0=False)
    banc.marqueurs(base, controle, tours=1)
    etat = json.load(open(os.path.join(controle, "etat.json")))
    r.verifier(etat["endpoint"] == "" and etat["dernier_handshake"] == 0,
               "sans interface, aucun endpoint et aucun handshake inventés", etat)
    r.fin("W-11 marqueurs prudents")

finally:
    banc.arreter()

sortir(r)
