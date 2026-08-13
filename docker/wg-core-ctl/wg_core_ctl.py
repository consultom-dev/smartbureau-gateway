#!/usr/bin/env python3
# =============================================================================
# wg-core-ctl — la surface de contrôle du peer wg-core (arbitrages Q17, Q20).
#
# Ce que ce processus EST, et ce qu'il n'est PAS :
#   - il est BRIDGÉ et SANS PRIVILÈGE : `gestion`/`gestion-worker` le joignent
#     comme `wg-core-ctl:8080`. Le netns hôte de `wg-core` (où vit `wg0`)
#     l'interdirait — un conteneur en netns hôte n'a pas de nom Docker
#     joignable depuis le pont de l'app (Q20) ;
#   - il ne voit JAMAIS `wg0`, ne détient AUCUN `cap`, ne route rien. Sa
#     seule arme est d'écrire un fichier : l'ÉTAT DÉSIRÉ des peers de
#     passerelle, que le rôle serveur de l'image `wg` réconcilie sur `wg0`
#     (annexe 1 §6.4). La frontière est un fichier — le motif
#     `parefeu-console`/`parefeu`.
#
# Il VALIDE avant d'écrire : rien de non vérifié (clé, allowed-ips) ne doit
# s'approcher d'un `wg set` en aval (défense en profondeur — c'est la leçon
# de l'injection dans /metrics, tranche 6 du lot 3). Bibliothèque standard
# seule : aucune dépendance à épingler ni à suivre (motif `parefeu-console`).
# =============================================================================
import base64
import ipaddress
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ETAT = os.environ.get("WG_CORE_CTL_ETAT", "/etc/wg-core-peers/peers.json")
PORT = int(os.environ.get("WG_CORE_CTL_PORT", "8080"))
# Le plan wg-core : les passerelles reçoivent un /32 dans ce /24 (l'app
# alloue premier-libre ≥ .2, annexe 1 §4.6). Un allowed-ips hors plan est
# refusé — jamais posé sur wg0.
PLAN = ipaddress.ip_network(os.environ.get("WG_CORE_CTL_PLAN", "10.100.0.0/24"))
GW_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
CORPS_MAX = 8192  # un peer tient dans quelques centaines d'octets

_verrou = threading.Lock()


def journal(msg):
    print("wg-core-ctl: %s" % msg, file=sys.stderr, flush=True)


# --- Validation : rien de non vérifié ne descend vers le `wg set` -----------
def cle_valide(cle):
    """Une clé publique WireGuard : base64 de 32 octets EXACTEMENT."""
    if not isinstance(cle, str) or len(cle) != 44 or not cle.endswith("="):
        return False
    try:
        return len(base64.b64decode(cle, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def allowed_valide(ip):
    """Un /32 hôte, dans le plan wg-core."""
    if not isinstance(ip, str):
        return False
    try:
        reseau = ipaddress.ip_network(ip, strict=True)
    except ValueError:
        return False
    return reseau.prefixlen == 32 and reseau.subnet_of(PLAN)


# --- État désiré : lu au démarrage, écrit ATOMIQUEMENT à chaque mutation -----
def charger():
    try:
        with open(ETAT) as f:
            donnees = json.load(f)
        return {p["gw_id"]: p for p in donnees.get("peers", [])}
    except (FileNotFoundError, ValueError, KeyError, TypeError):
        return {}


def ecrire(par_gw):
    """Sérialise TRIÉ (fichier stable, aucun brassage parasite) et publie par
    rename atomique : le rôle serveur ne lit jamais un fichier à moitié écrit."""
    peers = [par_gw[k] for k in sorted(par_gw)]
    tmp = ETAT + ".tmp"
    os.makedirs(os.path.dirname(ETAT) or ".", exist_ok=True)
    with open(tmp, "w") as f:
        json.dump({"peers": peers}, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, ETAT)


class Surface(BaseHTTPRequestHandler):
    server_version = "wg-core-ctl"

    def log_message(self, *a):  # journal maison, pas le format apache par défaut
        pass

    def _repondre(self, code, corps=None):
        charge = json.dumps(corps).encode() if corps is not None else b""
        self.send_response(code)
        if charge:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(charge)))
        self.end_headers()
        if charge:
            self.wfile.write(charge)

    def _corps(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n > CORPS_MAX:
            return None
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/sante":
            return self._repondre(200, {"etat": "ok"})
        if self.path == "/peers":
            with _verrou:
                par_gw = charger()
            return self._repondre(200, {"peers": [par_gw[k] for k in sorted(par_gw)]})
        return self._repondre(404, {"erreur": "route inconnue"})

    def do_POST(self):
        if self.path != "/peers":
            return self._repondre(404, {"erreur": "route inconnue"})
        try:
            corps = self._corps()
        except ValueError:
            return self._repondre(400, {"erreur": "corps JSON illisible"})
        if corps is None:
            return self._repondre(413, {"erreur": "corps trop grand"})
        gw = corps.get("gw_id") if isinstance(corps, dict) else None
        cle = corps.get("cle_publique") if isinstance(corps, dict) else None
        ip = corps.get("allowed_ips") if isinstance(corps, dict) else None
        if not (isinstance(gw, str) and GW_ID.match(gw)):
            return self._repondre(400, {"erreur": "gw_id invalide"})
        if not cle_valide(cle):
            return self._repondre(400, {"erreur": "cle_publique invalide"})
        if not allowed_valide(ip):
            return self._repondre(400, {"erreur": "allowed_ips hors plan wg-core"})
        with _verrou:
            par_gw = charger()
            par_gw[gw] = {"gw_id": gw, "cle_publique": cle, "allowed_ips": ip}
            ecrire(par_gw)
        journal("peer posé : %s → %s (%s)" % (gw, ip, cle[:8] + "…"))
        return self._repondre(204)

    def do_DELETE(self):
        prefixe = "/peers/"
        if not self.path.startswith(prefixe):
            return self._repondre(404, {"erreur": "route inconnue"})
        from urllib.parse import unquote
        gw = unquote(self.path[len(prefixe):])
        if not GW_ID.match(gw):
            return self._repondre(400, {"erreur": "gw_id invalide"})
        with _verrou:
            par_gw = charger()
            # Idempotent : retirer un peer absent est un succès (l'exécuteur
            # d'outbox peut rejouer un retrait — annexe 1 §3).
            if gw in par_gw:
                del par_gw[gw]
                ecrire(par_gw)
                journal("peer retiré : %s" % gw)
        return self._repondre(204)


def main():
    journal("écoute sur :%d, état désiré → %s, plan %s" % (PORT, ETAT, PLAN))
    ThreadingHTTPServer(("0.0.0.0", PORT), Surface).serve_forever()


if __name__ == "__main__":
    main()
