#!/usr/bin/env python3
# =============================================================================
# Cas S-01 … S-06 — la sonde de santé de la passerelle (annexe 3 §3.3).
#
# Fait foi : **annexe 3 §3.3** (les deux conditions) et **§8 invariant 2**
# (le DROP kit → kit EST le hub-and-spoke).
#
# Pourquoi une recette à part : la sonde est ce qui SORT une passerelle du
# service. Une sonde trop indulgente laisse un nœud relayer les kits entre
# eux en se déclarant sain — l'invariant 2 tombe, et rien ne le dit. Une
# sonde trop sévère fait tomber la flotte entière au premier hoquet. Les
# deux erreurs sont muettes : seule une recette les distingue.
#
# `wg` et `iptables` sont des doublures pilotées par des fichiers — ni
# noyau, ni privilèges, ni réseau.
#
#   Usage :  ./tests/sonde/lancer.py
# =============================================================================

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

SONDE = os.path.join(RACINE, "docker", "wg", "sonde.sh")
r = Recette(lot=4)

# `wg show <iface> latest-handshakes` : une ligne par peer, « clé date ».
# Le contenu vient de $BANC_HANDSHAKES ; toute autre invocation est TRACÉE,
# parce qu'une sonde qui écrit est une sonde qui masque.
DOUBLURE_WG = r"""#!/bin/sh
echo "wg $*" >> "$BANC_JOURNAL"
case "$3" in
  latest-handshakes) cat "$BANC_HANDSHAKES" 2>/dev/null ;;
esac
exit 0
"""

# `iptables -C <chaîne> <spec…>` : présent si la SPÉCIFICATION DEMANDÉE
# figure dans $BANC_REGLES.
#
# La doublure répond d'après ce qu'on lui demande, jamais d'après un
# drapeau du banc. Une doublure qui dirait « vrai » sans regarder ses
# arguments laisserait passer la mutation la plus intéressante : changer la
# règle que la sonde contrôle. Elle vérifierait alors n'importe quoi —
# `-o wg-core -j ACCEPT`, par exemple — en gardant son message d'erreur sur
# l'invariant 2, et S-05 certifierait le contraire de son titre.
DOUBLURE_IPTABLES = r"""#!/bin/sh
echo "iptables $*" >> "$BANC_JOURNAL"
verif=0
while [ $# -gt 0 ]; do
  case "$1" in
    -C) verif=1; shift; chaine="$1"; shift; break ;;
    *)  shift ;;
  esac
done
[ "$verif" = 1 ] || exit 0
# `-e` OBLIGATOIRE : le motif commence par « -A », que grep prendrait
# pour son option de contexte.
grep -qxF -e "-A $chaine $*" "$BANC_REGLES" 2>/dev/null
"""


class Banc:
    def __init__(self):
        self.racine = tempfile.mkdtemp(prefix="banc-sonde-")
        self.doublures = os.path.join(self.racine, "doublures")
        os.makedirs(self.doublures)
        for nom, contenu in (("wg", DOUBLURE_WG), ("iptables", DOUBLURE_IPTABLES)):
            chemin = os.path.join(self.doublures, nom)
            with open(chemin, "w") as f:
                f.write(contenu)
            os.chmod(chemin, 0o755)

    def arreter(self):
        shutil.rmtree(self.racine, ignore_errors=True)

    def sonder(self, nom, handshakes, drop=True):
        base = os.path.join(self.racine, nom)
        os.makedirs(base, exist_ok=True)
        chemin_h = os.path.join(base, "handshakes")
        with open(chemin_h, "w") as f:
            f.write(handshakes)
        chemin_r = os.path.join(base, "regles")
        with open(chemin_r, "w") as f:
            f.write("-A FORWARD -i wg-kits -o wg-kits -j DROP\n" if drop else "")
        self.journal = os.path.join(base, "appels.txt")
        env = dict(os.environ)
        env.update({
            "PATH": self.doublures + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "BANC_HANDSHAKES": chemin_h,
            "BANC_REGLES": chemin_r,
            "BANC_JOURNAL": self.journal,
        })
        return subprocess.run(["sh", SONDE], env=env, timeout=30,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def appels(self):
        if not os.path.exists(self.journal):
            return []
        with open(self.journal) as f:
            return f.read().splitlines()


def prerequis():
    if not os.path.isfile(SONDE):
        return "docker/wg/sonde.sh absent"
    for outil in ("sh", "awk"):
        if not shutil.which(outil):
            return "%s absent" % outil
    return None


NOMS = ["S-01 saine", "S-02 handshake vieilli", "S-03 aucun handshake",
        "S-04 interface muette", "S-05 isolation perdue", "S-06 sans effet de bord"]

MOTIF = prerequis()
if MOTIF:
    for nom in NOMS:
        r.cas(nom, "annexe 3 §3.3")
        r.sauter(nom, MOTIF)
    sortir(r)

banc = Banc()
maintenant = int(time.time())

try:
    # =========================================================================
    r.cas("S-01 — tunnel cœur frais et isolation en place : saine", "annexe 3 §3.3")
    acheve = banc.sonder("s01", "CLE-SERVEUR=\t%d\n" % (maintenant - 20))
    r.verifier(acheve.returncode == 0, "la sonde rend 0",
               acheve.stderr.decode())
    r.fin("S-01 saine")

    # =========================================================================
    r.cas("S-02 — handshake plus vieux que la fraîcheur : à sortir du service",
          "annexe 3 §3.3 ; arch. §7 (le watchdog des kits fera basculer)")
    # 200 s > 180 s : le tunnel cœur est mort, la passerelle est inutile aux
    # kits. La sonde le dit AVANT que leur watchdog ne les fasse partir.
    acheve = banc.sonder("s02", "CLE-SERVEUR=\t%d\n" % (maintenant - 200))
    r.verifier(acheve.returncode != 0, "la sonde rend un code non nul")
    r.verifier("wg-core" in acheve.stderr.decode(),
               "et elle dit LAQUELLE des deux conditions a manqué",
               acheve.stderr.decode())
    r.fin("S-02 handshake vieilli")

    # =========================================================================
    r.cas("S-03 — un peer sans aucun handshake ne vaut pas un handshake",
          "annexe 3 §3.3")
    # `0` est ce qu'écrit WireGuard pour « jamais » : le lire comme une date
    # rendrait la sonde verte sur un tunnel qui n'a jamais monté.
    acheve = banc.sonder("s03", "CLE-SERVEUR=\t0\n")
    r.verifier(acheve.returncode != 0, "la sonde rend un code non nul",
               acheve.stderr.decode())
    r.fin("S-03 aucun handshake")

    # =========================================================================
    r.cas("S-04 — interface absente : aucune ligne, donc aucune santé",
          "annexe 3 §3.3")
    # `wg show` muet, c'est l'interface qui n'existe pas. Une sonde dont le
    # `awk` conclurait « rien de périmé, donc tout va bien » certifierait
    # saine une passerelle sans tunnel du tout.
    acheve = banc.sonder("s04", "")
    r.verifier(acheve.returncode != 0, "la sonde rend un code non nul",
               acheve.stderr.decode())
    r.fin("S-04 interface muette")

    # =========================================================================
    r.cas("S-05 — isolation perdue : pire qu'inutile, et la sonde le dit",
          "annexe 3 §3.3 ; §8 invariant 2")
    # Tunnel cœur parfait, DROP kit → kit absent : la passerelle relaie
    # 10 000 kits les uns vers les autres. Une sonde qui ne regarderait que
    # le tunnel la laisserait EN SERVICE — c'est le cas qui justifie la
    # seconde condition.
    acheve = banc.sonder("s05", "CLE-SERVEUR=\t%d\n" % (maintenant - 5), drop=False)
    r.verifier(acheve.returncode != 0, "la sonde rend un code non nul")
    r.verifier("invariant 2" in acheve.stderr.decode(),
               "et elle nomme l'invariant cassé", acheve.stderr.decode())
    r.fin("S-05 isolation perdue")

    # =========================================================================
    r.cas("S-06 — aucun effet de bord : une sonde qui répare masque la panne",
          "annexe 3 §3.3")
    banc.sonder("s06", "CLE-SERVEUR=\t%d\n" % (maintenant - 5), drop=False)
    appels = banc.appels()
    r.verifier(not any(a.startswith("wg set") for a in appels),
               "aucun `wg set`", appels)
    r.verifier(not any(" -A " in a or " -I " in a or " -D " in a for a in appels),
               "aucune règle posée ni retirée — la sonde CONSTATE", appels)
    r.verifier(any(" -C " in a for a in appels),
               "elle n'a fait que vérifier", appels)
    r.fin("S-06 sans effet de bord")

finally:
    banc.arreter()

sortir(r)
