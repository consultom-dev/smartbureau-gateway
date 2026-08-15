#!/usr/bin/env python3
# =============================================================================
# Cas C-01 … C-08 — ce que le compose, le proxy et le provisionnement
# promettent, et qu'aucun banc réseau ne peut vérifier.
#
# Fait foi : **annexe 3 §5** (le proxy d'enrôlement), **§7** (le compose),
# **§2** (le provisionnement de l'hôte) et **§8** — invariants 3 (la
# surcharge `api.` vit dans le compose), 9 (deux routes, rien d'autre) et
# 10 (le wildcard se re-tire), plus la doctrine « sans état ».
#
# Ce sont des invariants de CONFIGURATION : ils se cassent en ajoutant une
# ligne, et se voient en la lisant. Ni Docker, ni réseau, ni privilège.
#
#   Usage :  ./tests/configuration/lancer.py
# =============================================================================

import os
import re
import shutil
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(os.path.dirname(ICI))
sys.path.insert(0, os.path.dirname(ICI))

from tap import Recette, sortir                                   # noqa: E402

r = Recette(lot=4)


def lire(*morceaux):
    with open(os.path.join(RACINE, *morceaux)) as f:
        return f.read()


COMPOSE = lire("docker-compose.yml")
NGINX = lire("docker", "proxy-enrolement", "nginx.conf.modele")
RELAIS = lire("docker", "proxy-enrolement", "relais.conf")
ENTREE_PROXY = lire("docker", "proxy-enrolement", "entrypoint.sh")
PROVISIONNEMENT = lire("provisionnement", "preparer.sh")
EXEMPLE = lire(".env.example")

# Le bloc d'un service, du nom jusqu'au prochain service de même
# indentation. Le nom peut être suivi d'un commentaire sur la même ligne.
def service(nom):
    motif = re.compile(r"^  %s:.*?\n(.*?)(?=^  \S|\Z)" % re.escape(nom), re.S | re.M)
    trouve = motif.search(COMPOSE)
    return trouve.group(1) if trouve else ""


# Le contenu SANS les commentaires : une interdiction ne doit pas être
# satisfaite (ni violée) par la prose qui l'explique.
def sans_commentaires(texte):
    return "\n".join(l for l in texte.splitlines() if not l.lstrip().startswith("#"))


# Les entrées de TOUS les blocs `volumes:` du compose — forme en liste
# comme forme en ligne. Chercher « - quelque-chose: » à la volée ramasse
# aussi les variables d'environnement (`- API=https://…`), et un motif
# rétréci pour les éviter finit par ne plus voir que les binds `./…` :
# c'est ainsi qu'un volume NOMMÉ passe inaperçu.
def montages_du_compose(texte):
    lignes, trouves, dedans, marge = texte.splitlines(), [], False, 0
    for ligne in lignes:
        nue = ligne.strip()
        if not nue:
            continue
        indent = len(ligne) - len(ligne.lstrip())
        if re.match(r"^volumes:\s*$", nue):
            dedans, marge = True, indent
            continue
        entree = re.match(r"^volumes:\s*\[(.*)\]\s*$", nue)
        if entree:
            trouves += [e.strip().strip('"\'').split(":")[0]
                        for e in entree.group(1).split(",") if e.strip()]
            continue
        if dedans:
            if nue.startswith("- ") and indent > marge:
                trouves.append(nue[2:].strip().strip('"\'').split(":")[0])
                continue
            dedans = False
    return trouves


try:
    # =========================================================================
    r.cas("C-01 — sans état : aucun volume de données dans le compose",
          "annexe 3 §7 ; doctrine « la panne se répare en redéployant »")
    # TOUS les montages, pas seulement les binds `./…` : un volume NOMMÉ
    # (`- etat-agent:/var/lib/wg-agent`) est exactement la donnée de valeur
    # que la doctrine interdit, et un motif qui n'accepte que `./` ne le
    # voit pas.
    montages = montages_du_compose(sans_commentaires(COMPOSE))
    r.verifier(sorted(set(montages)) == ["./tls", "./wg"],
               "les deux seuls montages portent des secrets tirés de Vault — "
               "aucune donnée de valeur, donc rien à restaurer", montages)
    # Le bloc `volumes:` de niveau supérieur se met par convention EN FIN de
    # fichier : le chercher dans l'en-tête ne prouvait rien. On le cherche
    # en colonne 0, où qu'il soit.
    r.verifier(not re.search(r"^volumes:", sans_commentaires(COMPOSE), re.M),
               "et aucun volume nommé déclaré au niveau supérieur")
    r.verifier(":ro" in service("enrolement-proxy"),
               "le certificat est monté en lecture seule")
    r.fin("C-01 sans état")

    # =========================================================================
    r.cas("C-02 — la surcharge `api.` vit dans le compose, sur CHAQUE conteneur "
          "qui parle au plan machine",
          "annexe 3 §8 invariant 3 ; arch. §12.3")
    for nom in ("agent", "enrolement-proxy"):
        bloc = service(nom)
        r.verifier("extra_hosts:" in bloc and "api.server.${DOMAINE}:10.100.0.1" in bloc,
                   "%s porte l'extra_hosts api. — sans lui il ne résout rien "
                   "et la passerelle naît muette" % nom, bloc[:200])
    r.verifier("extra_hosts" not in service("wireguard"),
               "`wireguard` ne l'a pas : il ne parle à personne (il pose des "
               "interfaces et des règles)")
    r.fin("C-02 surcharge api.")

    # =========================================================================
    r.cas("C-03 — `IFACES_PUBLIQUES` au conteneur qui pose les règles, et à lui seul",
          "arbitrage Q10 ; annexe 3 §8 invariant 7")
    r.verifier("IFACES_PUBLIQUES" in service("wireguard"),
               "`wireguard` la reçoit : c'est lui qui pose les règles")
    r.verifier("IFACES_PUBLIQUES" not in service("agent"),
               "l'agent de passerelle ne la reçoit PAS — il ne pose aucune "
               "règle, et un agent qui connaît les interfaces de sortie est un "
               "agent qu'on finira par faire poser des règles")
    r.fin("C-03 IFACES_PUBLIQUES")

    # =========================================================================
    r.cas("C-04 — le proxy d'enrôlement : deux routes, et RIEN d'autre",
          "annexe 3 §5 ; §8 invariant 9")
    # EXHAUSTIF : tout ce qui suit `location`, modificateur compris. Un
    # motif qui n'accepterait que `location <mot> {` et `location = <mot> {`
    # laisserait passer `location ~ ^/tout { … }` — une troisième route,
    # invisible, sur le seul service publiquement exposé du nœud.
    emplacements = re.findall(r"^\s*location\s+([^{]+?)\s*\{",
                              sans_commentaires(NGINX), re.M)
    r.verifier(sorted(re.sub(r"\s+", "", e) for e in emplacements)
               == ["/", "=/config-kit", "=/enroler"],
               "exactement deux routes exactes, plus le fourre-tout", emplacements)
    r.verifier(len(re.findall(r"\blocation\b", sans_commentaires(NGINX))) == 3,
               "et TROIS `location` dans le fichier, pas un de plus — le compte "
               "brut, qu'aucune forme de modificateur ne contourne",
               re.findall(r"^.*\blocation\b.*$", sans_commentaires(NGINX), re.M))
    r.verifier("return 404" in NGINX,
               "et le fourre-tout rend un 404 sec — pas de page bavarde")
    nginx_nu = sans_commentaires(NGINX).lower()
    r.verifier("acme" not in nginx_nu and "well-known" not in nginx_nu,
               "aucune troisième route ACME : le certificat vient de Vault")
    r.verifier("listen 80" not in NGINX,
               "et le port 80 n'est pas ouvert — aucun challenge ne s'exécute ici")
    r.verifier("limit_except POST" in NGINX and "limit_except GET" in NGINX,
               "chaque route n'accepte QUE son verbe")
    r.fin("C-04 deux routes")

    # =========================================================================
    r.cas("C-05 — durcissement du proxy : corps borné, débit limité, corps jamais journalisé",
          "annexe 3 §5 ; arch. §11.2 ; arbitrage A8")
    r.verifier("client_max_body_size    32k" in NGINX.replace("\t", " "),
               "corps de requête borné à 32 Ko (la borne porte sur les "
               "REQUÊTES — arbitrage A8)")
    r.verifier("limit_req_zone" in NGINX and "limit_conn_zone" in NGINX,
               "limitation de débit par IP source ET globale")
    r.verifier("limit_req_status 429" in NGINX, "et un 429 explicite")
    r.verifier("access_log" in NGINX and "$request_body" not in NGINX,
               "aucune journalisation de corps : les secrets y transitent")
    # UNE SEULE chaîne : « proxy_ssl_verify » d'un côté et « on; » de
    # l'autre étaient deux moitiés indépendantes — `proxy_ssl_server_name
    # on;`, deux lignes plus haut, satisfaisait la seconde, et
    # `proxy_ssl_verify off;` passait. Le proxy relaierait alors le
    # `POST /enroler` — la requête qui porte le secret d'usine — sans
    # vérifier la chaîne du plan de contrôle.
    r.verifier(re.search(r"proxy_ssl_verify\s+on\s*;", sans_commentaires(RELAIS)),
               "le relais vers le plan de contrôle vérifie le TLS amont",
               [l for l in RELAIS.splitlines() if "proxy_ssl" in l])
    r.verifier("X-Forwarded-For" in RELAIS,
               "et l'IP source du kit remonte — l'app en a besoin pour les "
               "rafales d'enrôlements échoués (annexe 4 §5)")
    r.fin("C-05 durcissement")

    # =========================================================================
    r.cas("C-06 — sans son wildcard, le proxy refuse de démarrer",
          "annexe 3 §8 invariant 10")
    r.verifier("cert.pem" in ENTREE_PROXY and "key.pem" in ENTREE_PROXY,
               "l'entrypoint vérifie les deux fichiers")
    # « un `exit 1` quelque part » ne prouve rien : il faut que le REFUS
    # soit attaché au CONTRÔLE des deux fichiers. On EXÉCUTE donc
    # l'entrypoint, deux fois, et on CONTRASTE — sans quoi le cas
    # confondrait « refuse à cause du certificat » avec « plante pour une
    # raison sans rapport », ce qui est arrivé : le banc passait `TLS` là où
    # le script lit `TLS_DIR`, et l'entrypoint échouait sur un modèle
    # introuvable en rendant le cas vert.
    def demarrer(certificats):
        bac = tempfile.mkdtemp()
        tls = os.path.join(bac, "tls")
        os.makedirs(tls)
        if certificats:
            for f in ("cert.pem", "key.pem"):
                with open(os.path.join(tls, f), "w") as sortie:
                    sortie.write("-----BEGIN CERTIFICATE----- (factice)\n")
        source = os.path.join(RACINE, "docker", "proxy-enrolement")
        modeles = os.path.join(bac, "modeles")
        os.makedirs(modeles)
        shutil.copy(os.path.join(source, "nginx.conf.modele"),
                    os.path.join(modeles, "nginx.conf.modele"))
        shutil.copy(os.path.join(source, "relais.conf"),
                    os.path.join(modeles, "relais.conf.modele"))
        # `nginx` en doublure : on teste le REFUS, pas le démarrage.
        faux = os.path.join(bac, "bin")
        os.makedirs(faux)
        with open(os.path.join(faux, "nginx"), "w") as sortie:
            sortie.write("#!/bin/sh\necho DEMARRE\nexit 0\n")
        os.chmod(os.path.join(faux, "nginx"), 0o755)
        return subprocess.run(
            ["sh", os.path.join(source, "entrypoint.sh")],
            env={"PATH": faux + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
                 "NOM": "gw-01.gateway.test", "API": "https://api.server.test",
                 "TLS_DIR": tls, "MODELES_DIR": modeles, "RENDUS_DIR": bac},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    sans = demarrer(certificats=False)
    avec = demarrer(certificats=True)
    r.verifier(sans.returncode != 0,
               "sans eux, il REFUSE de démarrer — un proxy qui écoute sans "
               "pouvoir servir ferme l'enrôlement ET le re-poll de toute la "
               "flotte servie, en ayant l'air vivant", sans.stderr.decode())
    r.verifier(b"gateway" in sans.stderr and b"Vault" in sans.stderr,
               "et son refus NOMME le certificat manquant", sans.stderr.decode())
    r.verifier(avec.returncode == 0 and b"DEMARRE" in avec.stdout,
               "alors qu'avec eux il démarre — le contraste, sans quoi le cas "
               "confondrait ce refus avec n'importe quelle autre panne",
               (avec.returncode, avec.stderr.decode()))
    r.fin("C-06 wildcard obligatoire")

    # =========================================================================
    r.cas("C-07 — aucun tag d'image mobile",
          "annexe 7 §8, invariant 1 ; CLAUDE.md")
    images = re.findall(r"image:\s*(\S+)", COMPOSE)
    r.verifier(all(i.startswith("${IMG_") for i in images),
               "toutes les images passent par une variable — le release.env "
               "de la release fixe les condensats", images)
    r.verifier(":latest" not in COMPOSE and ":latest" not in EXEMPLE,
               "et `latest` n'apparaît nulle part")
    r.fin("C-07 pas de tag mobile")

    # =========================================================================
    r.cas("C-08 — le provisionnement verrouille l'IPv6 et dimensionne conntrack",
          "annexe 3 §2.1 ; arch. §9 (v4 seul)")
    r.verifier("net.ipv4.ip_forward=1" in PROVISIONNEMENT, "le forwarding v4 est ouvert")
    r.verifier("net.ipv6.conf.all.forwarding=0" in PROVISIONNEMENT
               and "net.ipv6.conf.all.disable_ipv6=1" in PROVISIONNEMENT,
               "le v6 est VERROUILLÉ — un forwarding v6 ouvert contournerait "
               "en silence toutes les règles de l'annexe 3, qui ne raisonnent "
               "qu'en v4")
    r.verifier("nf_conntrack_max" in PROVISIONNEMENT
               and "nf_conntrack_buckets" in PROVISIONNEMENT,
               "conntrack et sa table de hachage sont dimensionnés ENSEMBLE : "
               "monter l'un sans l'autre allonge les chaînes au lieu "
               "d'augmenter la capacité")
    r.verifier("rp_filter=2" in PROVISIONNEMENT,
               "rp_filter en mode « loose » : avec deux chemins de sortie, le "
               "mode strict jette les retours légitimes sans trace")
    r.verifier("--dport 80" not in PROVISIONNEMENT,
               "et le pare-feu public n'ouvre pas le port 80")
    # Le pare-feu se POSE (arbitrage Q13). Le prouver ici tiendrait du
    # `grep` — c'est P-08 qui l'exécute en netns — mais deux propriétés du
    # SCRIPT se lisent, et elles ont coûté cher : que la pose soit une
    # commande, et que le `.env` ne passe pas le secret par un `sed`.
    r.verifier(re.search(r"\$IPT\s+-A INPUT", PROVISIONNEMENT),
               "les règles sont POSÉES par une commande, pas imprimées — une "
               "procédure de sécurité qui rend 0 sans avoir agi produit une "
               "confiance (arbitrage Q13 ; l'effet est tenu par P-08)")
    r.verifier(not re.search(r'sed[^\n]*AGENT_SECRET=\$AGENT_SECRET', PROVISIONNEMENT),
               "et le secret d'agent n'est pas injecté par un `sed` : un `&` "
               "ou un `\\` dans le secret produirait un `.env` FAUX, sans "
               "erreur — et le nœud prendrait des 401 indéfiniment")
    r.verifier("modprobe nf_conntrack" in PROVISIONNEMENT,
               "`nf_conntrack` est chargé avant `sysctl -p` : ses clés "
               "n'existent pas tant que le module ne l'est pas, et sur une VM "
               "neuve le script sortirait avant d'écrire le `.env`")
    r.fin("C-08 provisionnement")

finally:
    pass

sortir(r)
