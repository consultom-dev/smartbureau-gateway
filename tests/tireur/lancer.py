#!/usr/bin/env python3
# =============================================================================
# Cas TIR-01 … TIR-06 — le tireur (annexe 5 §5.3). On lève un VRAI Vault, on y
# dépose un certificat, on provisionne l'AppRole d'une passerelle, et on fait
# TOURNER le vrai conteneur `tireur` : il s'authentifie, compare la version,
# écrit le certificat atomiquement (640 root:smartbureau-lecture) et recharge.
# On éprouve ensuite la ROTATION, la PANNE INERTE (Vault scellé) et
# l'ISOLATION (un secret par machine, un chemin par machine).
#
# Requiert : docker + openssl. Images `hashicorp/vault:1.15.6` (tirée) et
# `consultom/tireur:dev` (bâtie ici).
# Usage :  python3 tests/tireur/lancer.py
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
from tap import Recette, sortir  # noqa: E402

IMG_VAULT = "hashicorp/vault:1.15.6"
IMG_TIREUR = "consultom/tireur:dev"
VAULT = "banc-tireur-vault-%d" % os.getpid()
ADDR = "http://127.0.0.1:8200"
TIREUR_DIR = os.path.join(RACINE, "docker", "tireur")


def docker(*a, entree=None):
    return subprocess.run(["docker", *a], input=entree, capture_output=True, text=True)


def vlt(jeton, *a, fmt=False):
    cmd = ["exec", "-e", "VAULT_ADDR=" + ADDR, "-e", "VAULT_TOKEN=" + (jeton or ""), VAULT, "vault", *a]
    if fmt:
        cmd.append("-format=json")
    r = docker(*cmd)
    return r.returncode, r.stdout, r.stderr


def openssl(*a):
    return subprocess.run(["openssl", *a], capture_output=True, text=True)


def cert_essai(rep, cn):
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
            "-keyout", os.path.join(rep, "key.pem"), "-out", os.path.join(rep, "cert.pem"),
            "-subj", "/CN=" + cn)


def tireur(bac, chemin, role_id, tours=1, recharge="touch /tls/.recharge"):
    return docker("run", "--rm", "--network", "container:" + VAULT,
                  "-e", "VAULT_ADDR=" + ADDR, "-e", "TIREUR_CHEMIN=" + chemin,
                  "-e", "TIREUR_ROLE_ID=" + role_id, "-e", "TIREUR_SECRET_ID=/secret/sid",
                  "-e", "TIREUR_SORTIE=/tls", "-e", "TIREUR_TOURS=%d" % tours,
                  "-e", "TIREUR_RECHARGE=" + recharge,
                  "-v", os.path.join(bac, "tls") + ":/tls",
                  "-v", os.path.join(bac, "secret") + ":/secret:ro",
                  IMG_TIREUR)


def main():
    r = Recette(lot=5)
    if not shutil.which("openssl"):
        for n in ("TIR-01", "TIR-02", "TIR-03", "TIR-04", "TIR-05", "TIR-06"):
            r.cas(n, "annexe 5 §5.3", lot="5a")
            r.sauter(n, "openssl absent")
        sortir(r)

    b = docker("build", "-t", IMG_TIREUR, TIREUR_DIR)
    bac = tempfile.mkdtemp(prefix="tireur-banc-")
    for d in ("certs", "tls", "secret"):
        os.makedirs(os.path.join(bac, d))
    os.chmod(os.path.join(bac, "tls"), 0o777)
    cert_essai(os.path.join(bac, "certs"), "gw-01.gateway.example")

    docker("run", "-d", "--name", VAULT, "--cap-add", "IPC_LOCK",
           "-v", os.path.join(bac, "certs") + ":/certs:ro",
           "-v", TIREUR_DIR + ":/prov:ro",
           "-e", "VAULT_DEV_ROOT_TOKEN_ID=racine", "-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
           IMG_VAULT)
    try:
        if b.returncode != 0:
            raise RuntimeError("build tireur: " + b.stderr[-200:])
        limite = time.time() + 40
        while time.time() < limite and vlt("racine", "status")[0] == 1:
            time.sleep(0.5)
        root = "racine"          # Vault en mode dev (déscellé, jeton racine connu)
        vlt(root, "secrets", "enable", "-path=kv", "-version=2", "kv")
        vlt(root, "kv", "put", "kv/tls/gateway", "certificat=@/certs/cert.pem", "cle=@/certs/key.pem")
        vlt(root, "kv", "put", "kv/tls/factory", "certificat=@/certs/cert.pem", "cle=@/certs/key.pem")
        prov = docker("exec", "-e", "VAULT_ADDR=" + ADDR, "-e", "VAULT_TOKEN=" + root,
                      VAULT, "sh", "/prov/provisionner-approle.sh", "gateway")
        conf = dict(l.split("=", 1) for l in prov.stdout.splitlines() if "=" in l and not l.startswith("#"))
        role_id = conf.get("role_id", "")
        with open(os.path.join(bac, "secret", "sid"), "w") as f:
            f.write(conf.get("secret_id_encapsule", ""))

        # =====================================================================
        r.cas("TIR-01 — le tireur va CHERCHER son certificat et l'écrit",
              "annexe 5 §5.3 (la machine tire, le central ne pousse jamais)", lot="5a")
        t = tireur(bac, "kv/tls/gateway", role_id)
        cert = os.path.join(bac, "tls", "cert.pem")
        cle = os.path.join(bac, "tls", "key.pem")
        r.verifier(role_id.startswith("") and conf.get("secret_id_encapsule"),
                   "provisionnement : role_id + secret_id ENCAPSULÉ rendus", prov.stdout[-160:] + prov.stderr[-160:])
        r.verifier(os.path.exists(cert) and os.path.exists(cle)
                   and os.path.getsize(cert) > 0 and os.path.getsize(cle) > 0,
                   "cert.pem et key.pem écrits, non vides", t.stderr[-200:])
        r.fin("TIR-01 tirage")

        # =====================================================================
        r.cas("TIR-02 — écriture ATOMIQUE, 640 root:smartbureau-lecture (GID 3000)",
              "annexe 5 §5.3", lot="5a")
        st = os.stat(cert)
        r.verifier(oct(st.st_mode & 0o777) == "0o640", "cert.pem en 640", oct(st.st_mode & 0o777))
        r.verifier(st.st_gid == 3000 and st.st_uid == 0,
                   "propriété root:smartbureau-lecture (GID 3000 figé)", "uid=%d gid=%d" % (st.st_uid, st.st_gid))
        r.fin("TIR-02 modes")

        # =====================================================================
        r.cas("TIR-03 — rechargement déclenché + version notée",
              "annexe 5 §5.3 (écrire puis recharger)", lot="5a")
        v1 = open(os.path.join(bac, "tls", ".version")).read().strip()
        r.verifier(os.path.exists(os.path.join(bac, "tls", ".recharge")),
                   "la commande de rechargement a été exécutée après l'écriture")
        r.verifier(v1 == "1", "la version locale suit celle du coffre (1)", v1)
        r.fin("TIR-03 rechargement")

        # =====================================================================
        r.cas("TIR-04 — ROTATION : nouvelle version dans Vault → réécriture",
              "annexe 5 §5.3 (comparer la version, écrire si différente)", lot="5a")
        os.remove(os.path.join(bac, "tls", ".recharge"))
        cert_essai(os.path.join(bac, "certs"), "gw-01-rotated.gateway.example")
        vlt(root, "kv", "put", "kv/tls/gateway", "certificat=@/certs/cert.pem", "cle=@/certs/key.pem")
        tireur(bac, "kv/tls/gateway", role_id)
        v2 = open(os.path.join(bac, "tls", ".version")).read().strip()
        r.verifier(v2 == "2" and os.path.exists(os.path.join(bac, "tls", ".recharge")),
                   "version 2 tirée et rechargée", v2)
        r.fin("TIR-04 rotation")

        # =====================================================================
        r.cas("TIR-05 — ISOLATION : un chemin par machine (§5.3)",
              "annexe 5 §5.3 (une passerelle ne lit pas kv/tls/factory)", lot="5a")
        jeton_gw = json.loads(vlt(root, "token", "create", "-policy=tireur-gateway", fmt=True)[1] or "{}")
        jeton_gw = (jeton_gw.get("auth") or {}).get("client_token", "")
        lit_gw = vlt(jeton_gw, "kv", "get", "kv/tls/gateway")[0] == 0
        lit_fa = vlt(jeton_gw, "kv", "get", "kv/tls/factory")
        r.verifier(lit_gw, "le tireur de passerelle LIT son chemin (kv/tls/gateway)")
        r.verifier(lit_fa[0] != 0 and ("permission denied" in lit_fa[2].lower() or "403" in lit_fa[2]),
                   "…et NE LIT PAS kv/tls/factory — un secret par machine, un chemin par machine",
                   lit_fa[2][-160:])
        r.fin("TIR-05 isolation")

        # =====================================================================
        # (Dernier : sceller Vault en mode dev est TERMINAL — aucun cas après.)
        r.cas("TIR-06 — PANNE INERTE : Vault scellé → le certificat reste",
              "annexe 5 §5.3 (la panne est inerte)", lot="5a")
        mtime_avant = os.stat(cert).st_mtime
        os.remove(os.path.join(bac, "tls", ".recharge"))
        vlt(root, "operator", "seal")
        t6 = tireur(bac, "kv/tls/gateway", role_id)
        r.verifier(os.path.exists(cert) and os.stat(cert).st_mtime == mtime_avant,
                   "cert.pem INCHANGÉ (ni effacé, ni tronqué) malgré Vault scellé")
        r.verifier(not os.path.exists(os.path.join(bac, "tls", ".recharge")) and t6.returncode == 0,
                   "aucun rechargement, le tireur sort proprement (il réessaiera)", t6.stderr[-160:])
        r.fin("TIR-06 panne inerte")
    finally:
        docker("rm", "-f", VAULT)
        shutil.rmtree(bac, ignore_errors=True)
    sortir(r)


if __name__ == "__main__":
    main()
