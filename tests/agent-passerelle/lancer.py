#!/usr/bin/env python3
# =============================================================================
# Cas G-01 … G-10 — la boucle de l'agent de passerelle, contre le mock
# (annexe 3 §4 ; critère de fini du lot 4, plan §6).
#
# Fait foi : **annexe 3 §4.1** (la boucle) et **§8** — invariants 5 (tous
# les peers), 6 (un agent sans plan de contrôle ne purge rien), 7 (aucune
# clé, aucune règle) et 8 (le diff porte sur `wg show`).
#
# Le mock est interrogé sur sa surface **plan-machine** : c'est ce que voit
# un agent de passerelle à travers wg-core (README du mock §2). `wg` et
# `ipset` sont des doublures qui portent un ÉTAT — une table de peers, un
# ensemble — que les commandes modifient réellement : on vérifie donc une
# convergence, pas qu'une commande a été appelée.
#
#   Usage :  ./tests/agent-passerelle/lancer.py
#            SMARTBUREAU_SERVER=/chemin/vers/smartbureau-server ./tests/…
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

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(os.path.dirname(ICI))
sys.path.insert(0, os.path.dirname(ICI))

from tap import Recette, sortir                                   # noqa: E402

AGENT = os.path.join(RACINE, "docker", "wg-agent", "agent.sh")
r = Recette(lot=4)

# --- Les doublures ----------------------------------------------------------
# `wg show <iface> dump` : la première ligne décrit l'interface, puis un peer
# par ligne — clé, psk, endpoint, allowed-ips, dernier handshake, rx, tx.
DOUBLURE_WG = r"""#!/bin/sh
echo "wg $*" >> "$BANC_JOURNAL"
case "$1" in
  show)
    [ "$3" = "dump" ] || exit 0
    printf 'CLE-PRIVEE\tCLE-PUBLIQUE\t51820\toff\n'
    cat "$BANC_PEERS" 2>/dev/null ;;
  set)
    # wg set <iface> peer <cle> allowed-ips <ips> | remove
    cle="$4"
    tmp="$(mktemp)"
    grep -v "^$cle	" "$BANC_PEERS" > "$tmp" 2>/dev/null || true
    if [ "$5" = "allowed-ips" ]; then
      printf '%s\t(none)\t(none)\t%s\t0\t0\t0\n' "$cle" "$6" >> "$tmp"
    fi
    mv "$tmp" "$BANC_PEERS" ;;
esac
exit 0
"""

DOUBLURE_IPSET = r"""#!/bin/sh
echo "ipset $*" >> "$BANC_JOURNAL"
[ -f "$BANC_IPSET" ] || exit 1          # ensemble absent : c'est un échec
case "$1" in
  list) printf 'Name: internet_ok\nMembers:\n'; cat "$BANC_IPSET" ;;
  add)  grep -qxF "$3" "$BANC_IPSET" || printf '%s\n' "$3" >> "$BANC_IPSET" ;;
  del)  tmp="$(mktemp)"; grep -vxF "$3" "$BANC_IPSET" > "$tmp" || true
        mv "$tmp" "$BANC_IPSET" ;;
esac
exit 0
"""

# `iptables` n'existe PAS pour cet agent : s'il l'appelait, la doublure le
# dirait (invariant 7 — il ne pose aucune règle).
DOUBLURE_IPTABLES = r"""#!/bin/sh
echo "IPTABLES-APPELE $*" >> "$BANC_JOURNAL"
exit 0
"""


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def corpus():
    chemin = os.environ.get("SMARTBUREAU_SERVER")
    if chemin:
        return chemin
    voisin = os.path.join(os.path.dirname(RACINE), "smartbureau-server")
    return voisin if os.path.isdir(voisin) else None


class Banc:
    def __init__(self):
        self.racine = tempfile.mkdtemp(prefix="banc-wg-agent-")
        self.doublures = os.path.join(self.racine, "doublures")
        os.makedirs(self.doublures)
        for nom, contenu in (("wg", DOUBLURE_WG), ("ipset", DOUBLURE_IPSET),
                             ("iptables", DOUBLURE_IPTABLES)):
            chemin = os.path.join(self.doublures, nom)
            with open(chemin, "w") as f:
                f.write(contenu)
            os.chmod(chemin, 0o755)
        self.port_machine = port_libre()
        self.port_proxy = port_libre()
        self.processus = None
        self.trace = os.path.join(self.racine, "mock.trace")

    def demarrer_mock(self, source):
        self.journal_mock = open(self.trace, "w")
        self.processus = subprocess.Popen(
            [sys.executable, "mock.py", "--adresse", "127.0.0.1",
             "--port", str(self.port_machine), "--port-proxy", str(self.port_proxy)],
            cwd=source, stdout=self.journal_mock, stderr=subprocess.STDOUT)
        for _ in range(200):
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
        return self.pilotage(methode, chemin, corps,
                             {"Authorization": "Bearer jeton-admin-de-developpement"})

    def enroler(self, secret, cle_publique):
        """Un kit de plus dans /peers — par la surface PROXY, comme un kit."""
        url = "http://127.0.0.1:%d/enroler" % self.port_proxy
        corps = json.dumps({"secret": secret, "cle_publique": cle_publique}).encode()
        requete = urllib.request.Request(url, data=corps, method="POST")
        requete.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(requete, timeout=10) as reponse:
            return json.loads(reponse.read())

    def reinitialiser(self):
        self.pilotage("POST", "/_mock/coupure/effacer", {})
        self.pilotage("POST", "/_mock/reinitialiser", {})

    # --- Le bac à sable -----------------------------------------------------

    def sable(self, nom, peers=(), ipset=()):
        base = os.path.join(self.racine, nom)
        os.makedirs(os.path.join(base, "etat"), exist_ok=True)
        with open(os.path.join(base, "peers"), "w") as f:
            for cle, ips in peers:
                f.write("%s\t(none)\t(none)\t%s\t0\t0\t0\n" % (cle, ips))
        if ipset is None:
            chemin = os.path.join(base, "ipset")
            if os.path.exists(chemin):
                os.remove(chemin)
        else:
            with open(os.path.join(base, "ipset"), "w") as f:
                f.write("".join(ip + "\n" for ip in ipset))
        return base

    def agent(self, base, tours=1, periode=0, timeout=60):
        env = {k: v for k, v in os.environ.items()
               if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        env.update({
            "PATH": self.doublures + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "no_proxy": "*",
            "API": "http://127.0.0.1:%d" % self.port_machine,
            "GW_ID": "gw1",
            "AGENT_SECRET": "secret-agent-gw1-de-developpement",
            "AGENT_ETAT": os.path.join(base, "etat"),
            "AGENT_TOURS": str(tours),
            "AGENT_PERIODE_S": str(periode),
            "AGENT_DELAI_HTTP_S": "5",
            "BANC_JOURNAL": os.path.join(base, "appels.txt"),
            "BANC_PEERS": os.path.join(base, "peers"),
            "BANC_IPSET": os.path.join(base, "ipset"),
        })
        return subprocess.run(["sh", AGENT], env=env, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    @staticmethod
    def peers(base):
        with open(os.path.join(base, "peers")) as f:
            return sorted(tuple(l.split("\t")[:4:3]) for l in f if l.strip())

    @staticmethod
    def ipset(base):
        chemin = os.path.join(base, "ipset")
        if not os.path.exists(chemin):
            return None
        with open(chemin) as f:
            return sorted(l.strip() for l in f if l.strip())

    @staticmethod
    def appels(base):
        chemin = os.path.join(base, "appels.txt")
        if not os.path.exists(chemin):
            return []
        with open(chemin) as f:
            return f.read().splitlines()

    def marque_trace(self):
        self.journal_mock.flush()
        return os.path.getsize(self.trace)

    def requetes_depuis(self, marque, motif):
        self.journal_mock.flush()
        with open(self.trace, errors="replace") as f:
            f.seek(marque)
            return [l for l in f.read().splitlines() if motif in l and "->" in l]


def prerequis():
    if not os.path.isfile(AGENT):
        return "docker/wg-agent/agent.sh absent"
    for outil in ("sh", "jq", "curl"):
        if not shutil.which(outil):
            return "%s absent" % outil
    source = corpus()
    if not source:
        return "smartbureau-server introuvable (SMARTBUREAU_SERVER=…)"
    if not os.path.isfile(os.path.join(source, "contrats", "mock", "mock.py")):
        return "mock du plan de contrôle absent de %s" % source
    return None


NOMS = ["G-01 premier pull", "G-02 304", "G-03 diff sur wg show",
        "G-04 401 ne purge rien", "G-05 API morte", "G-06 etat-tunnels",
        "G-07 fractionnement", "G-08 aucune clé, aucune règle",
        "G-09 version après application", "G-10 ipset d'un autre"]

MOTIF = prerequis()
if MOTIF:
    for nom in NOMS:
        r.cas(nom, "annexe 3 §4.1")
        r.sauter(nom, MOTIF)
    sortir(r)

banc = Banc()
if not banc.demarrer_mock(os.path.join(corpus(), "contrats", "mock")):
    banc.arreter()
    print("Bail out! le mock n'a pas démarré")
    sys.exit(1)

CLE_A0001 = "cle-publique-du-kit-A0001-de-recette="
CLE_A0009 = "RkFVWC1LSVQtQTAwMDkAAAAAAAAAAAAAAAAAAAAAAAA="

try:
    # =========================================================================
    r.cas("G-01 — premier pull : tous les peers servis sont posés, l'ipset suit",
          "annexe 3 §4.1 ; §8 invariants 1 et 5")
    banc.reinitialiser()
    banc.enroler("secret-usine-A0001-de-developpement", CLE_A0001)
    base = banc.sable("g01")
    acheve = banc.agent(base, tours=1)
    poses = dict(banc.peers(base))
    r.verifier(CLE_A0009 in poses and CLE_A0001 in poses,
               "les deux kits servis sont posés — TOUS les peers, pas une sélection "
               "locale (invariant 5)", poses)
    r.verifier(poses.get(CLE_A0009) == "10.200.0.9/32",
               "avec leur /32 servi", poses)
    r.verifier(banc.ipset(base) == ["10.200.0.9"],
               "l'ipset ne contient QUE les kits porteurs du drapeau internet "
               "(invariant 1 — elle plafonne)", banc.ipset(base))
    r.verifier(os.path.exists(os.path.join(base, "etat", "peers.version")),
               "et la version est mémorisée", acheve.stderr.decode()[-200:])
    r.fin("G-01 premier pull")

    # =========================================================================
    r.cas("G-02 — 304 : rien à faire, et rien n'est fait",
          "annexe 3 §4.1")
    avant = (banc.peers(base), banc.ipset(base))
    marque = banc.marque_trace()
    banc.agent(base, tours=1)
    appels = banc.requetes_depuis(marque, "/peers")
    r.verifier(appels and "-> 304" in appels[0], "le pull suivant est un 304", appels)
    r.verifier((banc.peers(base), banc.ipset(base)) == avant,
               "aucun peer touché, aucune entrée d'ipset touchée")
    r.verifier(not any(a.startswith("wg set") for a in banc.appels(base)[-5:]),
               "et aucun `wg set` émis")
    r.fin("G-02 304")

    # =========================================================================
    r.cas("G-03 — le diff porte sur `wg show`, jamais sur une liste mémorisée",
          "annexe 3 §8 invariant 8")
    # Quelqu'un pose un peer parasite à la main, et en efface un vrai. La
    # version n'a pas bougé côté serveur : un agent qui ferait confiance à sa
    # mémoire ne verrait rien. Celui-ci relit l'interface.
    with open(os.path.join(base, "peers"), "w") as f:
        f.write("CLE-PARASITE-POSEE-A-LA-MAIN=\t(none)\t(none)\t10.200.9.9/32\t0\t0\t0\n")
    # On force un 200 en oubliant la version mémorisée : c'est le cas d'un
    # redémarrage de conteneur, pas une astuce de test.
    os.remove(os.path.join(base, "etat", "peers.version"))
    banc.agent(base, tours=1)
    poses = dict(banc.peers(base))
    r.verifier(CLE_A0009 in poses and CLE_A0001 in poses,
               "les peers effacés à la main sont REPOSÉS", poses)
    r.verifier("CLE-PARASITE-POSEE-A-LA-MAIN=" not in poses,
               "et le peer parasite est RETIRÉ — le diff porte sur l'interface",
               poses)
    r.fin("G-03 diff sur wg show")

    # =========================================================================
    r.cas("G-04 — 401 : alerte, backoff, et AUCUNE purge",
          "annexe 3 §8 invariant 6 — « l'inverse ferait d'une panne du serveur une panne de flotte »")
    avant = (banc.peers(base), banc.ipset(base))
    env_ko = dict(os.environ)
    base_ko = banc.sable("g04", peers=[(CLE_A0009, "10.200.0.9/32")],
                         ipset=["10.200.0.9"])
    # Un secret d'agent inconnu : le mock rend 401 (annexe 1 §4.1).
    acheve = subprocess.run(
        ["sh", AGENT], timeout=60, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**{k: v for k, v in os.environ.items()
                if k.lower() not in ("http_proxy", "https_proxy", "no_proxy")},
             "PATH": banc.doublures + os.pathsep + os.environ.get("PATH", ""),
             "no_proxy": "*", "API": "http://127.0.0.1:%d" % banc.port_machine,
             "GW_ID": "gw1", "AGENT_SECRET": "secret-revoque",
             "AGENT_ETAT": os.path.join(base_ko, "etat"), "AGENT_TOURS": "1",
             "AGENT_PERIODE_S": "0", "AGENT_DELAI_HTTP_S": "5",
             "BANC_JOURNAL": os.path.join(base_ko, "appels.txt"),
             "BANC_PEERS": os.path.join(base_ko, "peers"),
             "BANC_IPSET": os.path.join(base_ko, "ipset")})
    r.verifier("401" in acheve.stderr.decode(), "le 401 est signalé",
               acheve.stderr.decode()[-200:])
    r.verifier(banc.peers(base_ko) == [(CLE_A0009, "10.200.0.9/32")],
               "les peers restent EN PLACE — la passerelle continue de servir",
               banc.peers(base_ko))
    r.verifier(banc.ipset(base_ko) == ["10.200.0.9"],
               "et l'ipset aussi : on ne vide pas « pour dépanner » (invariant 1)")
    r.verifier(not any(a.startswith("wg set") for a in banc.appels(base_ko)),
               "aucun `wg set` n'a été émis", banc.appels(base_ko))
    r.fin("G-04 401 ne purge rien")

    # =========================================================================
    r.cas("G-05 — API morte : même règle, aucune purge",
          "annexe 3 §8 invariant 6")
    base_mort = banc.sable("g05", peers=[(CLE_A0009, "10.200.0.9/32")],
                           ipset=["10.200.0.9"])
    banc.pilotage("POST", "/_mock/coupure", {"mode": "ecoute_fermee", "duree_s": 3})
    for _ in range(100):
        try:
            banc.pilotage("GET", "/_mock/sante")
            time.sleep(0.1)
        except Exception:
            break
    acheve = banc.agent(base_mort, tours=1)
    r.verifier(banc.peers(base_mort) == [(CLE_A0009, "10.200.0.9/32")],
               "peers intacts pendant que l'API est morte", banc.peers(base_mort))
    r.verifier("RESTENT en place" in acheve.stderr.decode(),
               "et l'agent de passerelle le dit", acheve.stderr.decode()[-200:])
    for _ in range(200):
        try:
            banc.pilotage("GET", "/_mock/sante")
            break
        except Exception:
            time.sleep(0.1)
    banc.pilotage("POST", "/_mock/coupure/effacer", {})
    r.fin("G-05 API morte")

    # =========================================================================
    r.cas("G-06 — `POST /etat-tunnels` : le delta, et rien que le delta",
          "annexe 3 §4.1 ; annexe 1 §4.2")
    base6 = banc.sable("g06", peers=[], ipset=[])
    banc.agent(base6, tours=1)                       # pose les peers
    # Un handshake apparaît : c'est ce que le dump remonterait.
    with open(os.path.join(base6, "peers"), "w") as f:
        f.write("%s\t(none)\t(none)\t10.200.0.9/32\t1754476301\t123\t456\n" % CLE_A0009)
    marque = banc.marque_trace()
    banc.agent(base6, tours=1)
    envois = banc.requetes_depuis(marque, "/etat-tunnels")
    r.verifier(envois and "-> 204" in envois[0], "le delta part et le serveur l'accepte",
               envois)
    marque = banc.marque_trace()
    banc.agent(base6, tours=1)
    r.verifier(not banc.requetes_depuis(marque, "/etat-tunnels"),
               "et il ne repart PAS : ce qui n'a pas changé n'est pas un delta",
               banc.requetes_depuis(marque, "/etat-tunnels"))
    r.fin("G-06 etat-tunnels")

    # =========================================================================
    r.cas("G-07 — un gros delta se FRACTIONNE, il ne se tronque pas",
          "arbitrage A8 ; annexe 3 §4.1")
    base7 = banc.sable("g07", peers=[], ipset=[])
    banc.agent(base7, tours=1)
    with open(os.path.join(base7, "peers"), "w") as f:
        for i in range(1, 451):
            f.write("CLE-KIT-%03d=\t(none)\t(none)\t10.200.1.%d/32\t17544763%02d\t1\t2\n"
                    % (i, i % 254 + 1, i % 100))
    marque = banc.marque_trace()
    acheve = banc.agent(base7, tours=1)
    envois = banc.requetes_depuis(marque, "/etat-tunnels")
    r.verifier(len(envois) >= 3,
               "450 lignes partent en PLUSIEURS requêtes (lot de 200)", len(envois))
    r.verifier(all("-> 204" in e for e in envois), "toutes acceptées", envois)
    r.verifier("fractionné" in acheve.stderr.decode(),
               "et l'agent de passerelle le dit — un état tronqué ferait compter "
               "des kits vivants comme silencieux", acheve.stderr.decode()[-300:])
    r.fin("G-07 fractionnement")

    # =========================================================================
    r.cas("G-08 — aucune clé, aucune règle : le cloisonnement est vérifiable",
          "annexe 3 §4.2 ; §8 invariant 7 ; arbitrage Q10")
    source = open(AGENT).read()
    code = "\n".join(l for l in source.splitlines() if not l.lstrip().startswith("#"))
    for interdit in ("genkey", "privatekey", "PrivateKey", "wg-quick", "/etc/wireguard"):
        r.verifier(interdit not in code,
                   "l'agent de passerelle ne touche pas à « %s »" % interdit)
    r.verifier("iptables" not in code and "nft " not in code,
               "et il ne pose aucune règle de pare-feu")
    r.verifier("IFACES_PUBLIQUES" not in code,
               "il ne connaît même pas les interfaces de sortie (arbitrage Q10)")
    tous = banc.appels(base) + banc.appels(base6) + banc.appels(base7)
    r.verifier(not any(a.startswith("IPTABLES-APPELE") for a in tous),
               "et aucune exécution n'a appelé iptables",
               [a for a in tous if a.startswith("IPTABLES")])
    r.fin("G-08 aucune clé, aucune règle")

    # =========================================================================
    r.cas("G-09 — la version n'est mémorisée qu'APRÈS application",
          "annexe 3 §4.1")
    base9 = banc.sable("g09", peers=[], ipset=None)   # ipset ABSENTE
    banc.agent(base9, tours=1)
    version = os.path.join(base9, "etat", "peers.version")
    r.verifier(dict(banc.peers(base9)),
               "les peers sont posés (ce qui pouvait l'être l'a été)")
    r.verifier(os.path.exists(version),
               "et la version est mémorisée : l'ipset absente n'est pas un échec "
               "d'application — elle appartient au conteneur `wg`")
    r.fin("G-09 version après application")

    # =========================================================================
    r.cas("G-10 — l'ipset appartient au conteneur `wg`, pas à l'agent de passerelle",
          "annexe 3 §3.2 et §4.1 — un seul propriétaire par objet")
    r.verifier(banc.ipset(base9) is None,
               "l'ensemble absent le reste — deux propriétaires pour un même "
               "objet, c'est la panne au premier `compose stop`")
    r.verifier(not any(a.startswith("ipset create") for a in banc.appels(base9)),
               "aucun `ipset create` n'a été tenté", banc.appels(base9))
    # La version est mémorisée : le tour suivant serait un 304, qui ne
    # regarde même pas l'ipset. On l'efface pour forcer un 200 — c'est le
    # cas d'un redémarrage de conteneur.
    os.remove(os.path.join(base9, "etat", "peers.version"))
    acheve = banc.agent(base9, tours=1)
    r.verifier("ne l'a pas encore créée" in acheve.stderr.decode(),
               "et l'agent de passerelle le signale, plutôt que de la créer",
               acheve.stderr.decode()[-300:])
    r.fin("G-10 ipset d'un autre")

finally:
    banc.arreter()

sortir(r)
