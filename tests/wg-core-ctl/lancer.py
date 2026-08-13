#!/usr/bin/env python3
# =============================================================================
# Cas CTL-01 … CTL-06 — la surface de contrôle wg-core-ctl (arbitrages Q17,
# Q20). On l'exécute avec le `python3` de l'HÔTE (comme parefeu-console) :
# la surface n'utilise que la bibliothèque standard, aucune image à bâtir.
#
# Ce que ces cas prouvent : le CONTRAT dont l'app dépend (POST/DELETE /peers),
# la VALIDATION (rien de non vérifié n'est écrit — défense en profondeur),
# l'écriture ATOMIQUE et TRIÉE, l'idempotence du retrait, la persistance de
# l'état désiré au redémarrage.
#
# Usage :  ./tests/wg-core-ctl/lancer.py     (aucun privilège requis)
# =============================================================================
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(os.path.dirname(ICI))
SURFACE = os.path.join(RACINE, "docker", "wg-core-ctl", "wg_core_ctl.py")
sys.path.insert(0, os.path.dirname(ICI))
from tap import Recette, sortir  # noqa: E402

import base64  # noqa: E402

PORT = 18000 + (os.getpid() % 1000)
BASE = "http://127.0.0.1:%d" % PORT
# Une clé publique WireGuard = base64 de 32 octets EXACTEMENT (44 car.).
CLE_OK = base64.b64encode(bytes(range(32))).decode()
CLE_OK2 = base64.b64encode(bytes(range(31, -1, -1))).decode()


def demande(methode, chemin, corps=None):
    """(code, corps décodé ou None). Un 4xx n'est pas une exception ici."""
    donnees = json.dumps(corps).encode() if corps is not None else None
    req = urllib.request.Request(BASE + chemin, data=donnees, method=methode)
    if donnees is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            brut = r.read()
            return r.status, (json.loads(brut) if brut else None)
    except urllib.error.HTTPError as e:
        brut = e.read()
        try:
            return e.code, (json.loads(brut) if brut else None)
        except ValueError:
            return e.code, None


def demande_brute(chemin, octets):
    """POST d'un corps NON-JSON (pour le cas du corps illisible)."""
    req = urllib.request.Request(BASE + chemin, data=octets, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def etat_fichier(chemin):
    try:
        with open(chemin) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return None


def demarrer(etat):
    env = dict(os.environ, WG_CORE_CTL_PORT=str(PORT), WG_CORE_CTL_ETAT=etat)
    proc = subprocess.Popen([sys.executable, SURFACE], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    limite = time.time() + 10
    while time.time() < limite:
        try:
            if demande("GET", "/sante")[0] == 200:
                return proc
        except urllib.error.URLError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("wg-core-ctl n'a pas démarré")


def main():
    r = Recette(lot=2)
    bac = os.path.join(os.environ.get("TMPDIR", "/tmp"),
                       "wg-core-ctl-banc-%d" % os.getpid())
    os.makedirs(bac, exist_ok=True)
    etat = os.path.join(bac, "peers.json")
    proc = demarrer(etat)
    try:
        # ---------------------------------------------------------------------
        r.cas("CTL-01 — POST /peers valide : 204, entrée écrite atomiquement",
              "annexe 1 §6.4 ; contrat Q20", lot="2 étendu")
        code, _ = demande("POST", "/peers", {
            "gw_id": "gw-01", "cle_publique": CLE_OK, "allowed_ips": "10.100.0.2/32"})
        r.verifier(code == 204, "POST valide : 204", code)
        f = etat_fichier(etat)
        r.verifier(f and f.get("peers") == [
            {"gw_id": "gw-01", "cle_publique": CLE_OK, "allowed_ips": "10.100.0.2/32"}],
            "peers.json porte l'entrée, une seule", f)
        r.fin("CTL-01 pose valide")

        # ---------------------------------------------------------------------
        r.cas("CTL-02 — validation : rien de non vérifié n'est écrit (400)",
              "annexe 1 §6.4 (défense en profondeur) ; leçon /metrics", lot="2 étendu")
        avant = etat_fichier(etat)
        c_cle, _ = demande("POST", "/peers", {
            "gw_id": "gw-x", "cle_publique": "trop-court=", "allowed_ips": "10.100.0.3/32"})
        r.verifier(c_cle == 400, "clé publique invalide : 400", c_cle)
        c_ip, _ = demande("POST", "/peers", {
            "gw_id": "gw-x", "cle_publique": CLE_OK, "allowed_ips": "192.168.0.5/32"})
        r.verifier(c_ip == 400, "allowed_ips hors plan wg-core : 400", c_ip)
        c_ip2, _ = demande("POST", "/peers", {
            "gw_id": "gw-x", "cle_publique": CLE_OK, "allowed_ips": "10.100.0.0/24"})
        r.verifier(c_ip2 == 400, "allowed_ips non /32 : 400", c_ip2)
        c_gw, _ = demande("POST", "/peers", {
            "gw_id": "gw x/../", "cle_publique": CLE_OK, "allowed_ips": "10.100.0.3/32"})
        r.verifier(c_gw == 400, "gw_id invalide : 400", c_gw)
        c_brut = demande_brute("/peers", b"{ ceci n'est pas du json")
        r.verifier(c_brut == 400, "corps JSON illisible : 400", c_brut)
        r.verifier(etat_fichier(etat) == avant,
                   "AUCUNE de ces requêtes n'a modifié l'état désiré")
        r.fin("CTL-02 validation")

        # ---------------------------------------------------------------------
        r.cas("CTL-03 — POST re-joué sur le même gw_id : remplace, ne double pas",
              "contrat Q20 (upsert)", lot="2 étendu")
        demande("POST", "/peers", {
            "gw_id": "gw-01", "cle_publique": CLE_OK2, "allowed_ips": "10.100.0.9/32"})
        f = etat_fichier(etat)
        gw01 = [p for p in f["peers"] if p["gw_id"] == "gw-01"]
        r.verifier(len(gw01) == 1 and gw01[0]["allowed_ips"] == "10.100.0.9/32"
                   and gw01[0]["cle_publique"] == CLE_OK2,
                   "une seule entrée gw-01, mise à jour (clé et /32 neufs)", f)
        r.fin("CTL-03 upsert")

        # ---------------------------------------------------------------------
        r.cas("CTL-04 — DELETE /peers/{gw_id} : 204, retrait, et idempotent",
              "contrat Q20 ; rejeu d'outbox (annexe 1 §3)", lot="2 étendu")
        c1, _ = demande("DELETE", "/peers/gw-01")
        r.verifier(c1 == 204, "retrait d'un présent : 204", c1)
        f = etat_fichier(etat)
        r.verifier(not any(p["gw_id"] == "gw-01" for p in f["peers"]),
                   "gw-01 n'est plus dans l'état désiré")
        c2, _ = demande("DELETE", "/peers/gw-01")
        r.verifier(c2 == 204, "retrait rejoué (absent) : 204 quand même — idempotent", c2)
        r.fin("CTL-04 retrait idempotent")

        # ---------------------------------------------------------------------
        r.cas("CTL-05 — plusieurs peers : fichier TRIÉ (stable), GET /peers fidèle",
              "contrat de fichier Q20 (état stable, aucun brassage)", lot="2 étendu")
        for gw, ip in [("gw-03", "10.100.0.5/32"), ("gw-02", "10.100.0.4/32")]:
            demande("POST", "/peers", {"gw_id": gw, "cle_publique": CLE_OK, "allowed_ips": ip})
        f = etat_fichier(etat)
        ids = [p["gw_id"] for p in f["peers"]]
        r.verifier(ids == sorted(ids), "peers.json est trié par gw_id", ids)
        code, corps = demande("GET", "/peers")
        r.verifier(code == 200 and [p["gw_id"] for p in corps["peers"]] == ids,
                   "GET /peers reflète l'état écrit", corps)
        r.fin("CTL-05 tri stable")

        # ---------------------------------------------------------------------
        r.cas("CTL-06 — redémarrage : l'état désiré est rechargé, pas perdu",
              "contrat de fichier Q20 (survit au redémarrage)", lot="2 étendu")
        avant = [p["gw_id"] for p in etat_fichier(etat)["peers"]]
        proc.terminate()
        proc.wait(timeout=5)
        proc2 = demarrer(etat)
        try:
            _, corps = demande("GET", "/peers")
            r.verifier([p["gw_id"] for p in corps["peers"]] == avant,
                       "après relance, le même état désiré est servi", corps)
        finally:
            proc2.terminate()
            proc2.wait(timeout=5)
            proc = None
        r.fin("CTL-06 persistance")
    finally:
        if proc:
            proc.terminate()
            proc.wait(timeout=5)
        import shutil
        shutil.rmtree(bac, ignore_errors=True)
    sortir(r)


if __name__ == "__main__":
    main()
