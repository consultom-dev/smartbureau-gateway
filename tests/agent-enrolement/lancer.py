#!/usr/bin/env python3
# =============================================================================
# Cas A-01 … A-17 — la machine à états de l'agent d'enrôlement, rejouée
# contre le mock du plan de contrôle (critère de fini 1 du lot 2, plan §4 :
# « la machine à états est rejouée contre le mock, avec des coupures
# simulées à chaque étape et une reprise idempotente »).
#
# Fait foi : **annexe 2 §3.2** (l'état local — fichiers, modes,
# propriétaires) et **§3.3** (les états et leurs transitions).
#
# Ce banc ne demande NI privilège réseau NI module noyau : il recette la
# machine à états et les écritures d'état, pas WireGuard. Les interfaces
# sont l'affaire de `tests/roles/`, qui se déclare sauté là où le module
# manque. Les deux se complètent, aucun ne se remplace.
#
#   Usage :  ./tests/agent-enrolement/lancer.py
#            SMARTBUREAU_SERVER=/chemin/vers/smartbureau-server ./tests/…
# =============================================================================

import json
import os
import sys
import time

ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(ICI))
sys.path.insert(0, ICI)

from tap import Recette, sortir                                  # noqa: E402
from banc import (Banc, GID_LECTURE, corpus, empreintes, lire,   # noqa: E402
                  lire_json, mode, proprietaire)

r = Recette(lot=2)


def prerequis():
    """Un prérequis manquant fait un cas SAUTÉ, jamais un cas vert."""
    if os.geteuid() != 0:
        return "root requis (l'agent d'enrôlement pose des modes et un GID)"
    for outil in ("curl", "jq", "sh"):
        if not any(os.access(os.path.join(c, outil), os.X_OK)
                   for c in os.environ.get("PATH", "").split(os.pathsep)):
            return "%s absent" % outil
    source = corpus()
    if not source:
        return "smartbureau-server introuvable (SMARTBUREAU_SERVER=…)"
    if not os.path.isfile(os.path.join(source, "contrats", "mock", "mock.py")):
        return "mock du plan de contrôle absent de %s" % source
    return None


MOTIF = prerequis()
if MOTIF:
    for numero, nom in enumerate([
            "A-01 enrôlement", "A-02 clé du kit", "A-03 réponse perdue après traitement",
            "A-04 réponse perdue avant traitement", "A-05 403 d'enrôlement",
            "A-06 re-poll 200", "A-07 re-poll 304", "A-08 release_cible",
            "A-09 suspension et reprise", "A-10 identité perdue",
            "A-11 identité perdue avec amorce", "A-12 identité perdue sans porteur",
            "A-13 repli sur l'IP", "A-14 rotation de clé", "A-15 coupures",
            "A-16 cadences et invariant 6", "A-17 ordre des écritures"], 1):
        r.cas(nom, "annexe 2 §3.3")
        r.sauter(nom, MOTIF)
    sortir(r)

banc = Banc()
if not banc.demarrer_mock(os.path.join(corpus(), "contrats", "mock")):
    banc.arreter()
    print("Bail out! le mock n'a pas démarré")
    sys.exit(1)


def enroler(nom, **kwargs):
    """Amène un bac à sable de l'état USINE à l'état NOMINAL."""
    banc.reinitialiser()
    base, controle, conf = banc.sable(nom)
    banc.poser_usine(controle, **kwargs)
    acheve, _ = banc.agent(base, controle, conf, tours=1)
    return base, controle, conf, acheve


try:
    # =========================================================================
    r.cas("A-01 — USINE → NOMINAL : l'ordre des écritures, les modes, les propriétaires",
          "annexe 2 §3.2 et §3.3 ; invariants 2, 3, 5, 12")
    base, controle, conf, acheve = enroler("a01")

    r.verifier(not os.path.exists(os.path.join(controle, "usine.json")),
               "usine.json supprimé à l'enrôlement réussi (invariant 2)",
               acheve.stderr.decode())
    attendus = {
        "secret_api": ("640", GID_LECTURE),
        "applicatif.json": ("640", GID_LECTURE),
        "domaines.json": ("644", None),
        "endpoints.txt": ("644", None),
        "port": ("644", None),
        "repoll.txt": ("644", None),
        "endpoints.version": ("644", None),
        "etat-agent.json": ("644", None),
    }
    for nom, (attendu, groupe) in attendus.items():
        chemin = os.path.join(controle, nom)
        if not r.verifier(os.path.exists(chemin), "%s écrit" % nom):
            continue
        r.verifier(mode(chemin) == attendu,
                   "%s en %s" % (nom, attendu), "obtenu %s" % mode(chemin))
        uid, gid = proprietaire(chemin)
        r.verifier(uid == 0, "%s appartient à root" % nom)
        if groupe is not None:
            r.verifier(gid == groupe,
                       "%s au GID %d (smartbureau-lecture, figé)" % (nom, groupe),
                       "obtenu %d" % gid)

    for nom, attendu in (("wg0.conf", "600"), ("cle_privee", "600")):
        chemin = os.path.join(conf, nom)
        if r.verifier(os.path.exists(chemin), "%s écrit" % nom):
            r.verifier(mode(chemin) == attendu, "%s en %s (il porte la clé du kit)" % (nom, attendu),
                       "obtenu %s" % mode(chemin))

    lignes = lire(os.path.join(controle, "endpoints.txt")).split()
    r.verifier(lignes and all(l.replace(".", "").isdigit() for l in lignes),
               "endpoints.txt ne contient que des IP (invariant 5)", lignes)
    couples = [l.split() for l in lire(os.path.join(controle, "repoll.txt")).splitlines() if l]
    r.verifier(couples and all(len(c) == 2 and not c[0].replace(".", "").isdigit()
                               for c in couples),
               "repoll.txt en couples « nom IP » (arbitrage L4)", couples)
    conf_wg0 = lire(os.path.join(conf, "wg0.conf"))
    r.verifier("Table = off" in conf_wg0 and "AllowedIPs = 0.0.0.0/0" in conf_wg0,
               "wg0.conf : AllowedIPs = 0.0.0.0/0 AVEC Table = off (piège 11)")
    r.verifier("MTU = 1360" in conf_wg0, "wg0.conf : MTU 1360 (arch. §6.2)")
    r.verifier(lire_json(os.path.join(controle, "etat-agent.json"))["etat"] == "enrole",
               "etat-agent.json annonce l'état enrole (§3.2)")
    r.fin("A-01 enrôlement")

    # =========================================================================
    r.cas("A-02 — la clé du kit naît AVANT le premier POST, et une seule fois",
          "annexe 2 §3.5 ; annexe 1 §4.3, invariant 8")
    base, controle, conf, _ = enroler("a02")
    appels = banc.appels_wg(base)
    r.verifier(sum(1 for a in appels if a.startswith("wg genkey")) == 1,
               "`wg genkey` appelé exactement une fois", appels)
    privee = lire(os.path.join(conf, "cle_privee")).strip()
    publique = "publique-de-" + privee
    etat_mock = banc.pilotage("GET", "/_mock/etat")
    kit = [k for k in etat_mock["kits"] if k["kit_id"] == "A0001"][0]
    r.verifier(kit["cle_publique"] == publique,
               "le serveur a enregistré la clé publique DÉRIVÉE du fichier persisté",
               "serveur=%s local=%s" % (kit.get("cle_publique"), publique))
    # Deuxième exécution : rien ne doit régénérer la clé.
    banc.agent(base, controle, conf, tours=1)
    r.verifier(sum(1 for a in banc.appels_wg(base) if a.startswith("wg genkey")) == 1,
               "un second démarrage ne régénère pas la clé (le rejeu resterait idempotent)")
    r.fin("A-02 clé du kit")

    # =========================================================================
    r.cas("A-03 — le cas dur : réponse perdue APRÈS traitement, puis rejeu",
          "annexe 1 §4.3 et invariant 8 ; README du mock §4")
    banc.reinitialiser()
    base, controle, conf = banc.sable("a03")
    banc.poser_usine(controle)
    # Le serveur consomme le secret, alloue le /32… puis la connexion tombe.
    banc.pilotage("POST", "/_mock/coupure",
                  {"mode": "apres", "routes": ["/enroler"], "appels": 1})
    acheve, _ = banc.agent(base, controle, conf, tours=1)
    r.verifier(os.path.exists(os.path.join(controle, "usine.json")),
               "réponse perdue : usine.json est CONSERVÉ (rien n'a été écrit côté kit)")
    r.verifier(not os.path.exists(os.path.join(controle, "secret_api")),
               "aucun secret_api écrit sur une réponse perdue")
    etat_mock = banc.pilotage("GET", "/_mock/etat")
    kit = [k for k in etat_mock["kits"] if k["kit_id"] == "A0001"][0]
    adresse_serveur = kit["adresse"]
    r.verifier(adresse_serveur is not None,
               "côté serveur, la transition a bien eu lieu (le /32 est alloué)")
    # Le rejeu, avec le MÊME couple secret + clé publique.
    acheve, _ = banc.agent(base, controle, conf, tours=1)
    r.verifier(not os.path.exists(os.path.join(controle, "usine.json")),
               "au rejeu : enrôlement abouti, usine.json supprimé", acheve.stderr.decode())
    r.verifier(lire(os.path.join(conf, "wg0.conf")).find("Address = " + adresse_serveur) >= 0,
               "le rejeu rend la MÊME adresse — aucun second /32 (invariant 8)",
               adresse_serveur)
    etat_mock = banc.pilotage("GET", "/_mock/etat")
    kits = [k for k in etat_mock["kits"] if k["adresse"] == adresse_serveur]
    r.verifier(len(kits) == 1, "un seul kit porte ce /32 — rien n'a été consommé deux fois")
    r.verifier(sum(1 for a in banc.appels_wg(base) if a.startswith("wg genkey")) == 1,
               "et toujours une seule clé privée : c'est ce qui rend le rejeu idempotent")
    r.fin("A-03 réponse perdue après traitement")

    # =========================================================================
    r.cas("A-04 — réponse perdue AVANT traitement : le kit reste en USINE",
          "annexe 2 §3.3 ; README du mock §7")
    banc.reinitialiser()
    base, controle, conf = banc.sable("a04")
    banc.poser_usine(controle)
    banc.pilotage("POST", "/_mock/coupure",
                  {"mode": "avant", "routes": ["/enroler"], "appels": 1})
    banc.agent(base, controle, conf, tours=1)
    r.verifier(os.path.exists(os.path.join(controle, "usine.json")),
               "usine.json conservé : rien n'a été traité")
    r.verifier(os.path.exists(os.path.join(conf, "cle_privee")),
               "la clé privée est DÉJÀ là — elle précède l'appel, pas la réponse")
    etat_mock = banc.pilotage("GET", "/_mock/etat")
    kit = [k for k in etat_mock["kits"] if k["kit_id"] == "A0001"][0]
    r.verifier(kit["etat"] == "fabrique", "côté serveur, aucune transition", kit["etat"])
    r.verifier(lire_json(os.path.join(controle, "etat-agent.json"))["etat"] == "usine",
               "etat-agent.json reste en usine")
    banc.pilotage("POST", "/_mock/coupure/effacer", {})
    banc.agent(base, controle, conf, tours=1)
    r.verifier(not os.path.exists(os.path.join(controle, "usine.json")),
               "la coupure levée, le tour suivant enrôle — la boucle ne s'est jamais arrêtée")
    r.fin("A-04 réponse perdue avant traitement")

    # =========================================================================
    r.cas("A-05 — 403 sur /enroler : alerte locale, ET ON CONTINUE D'ESSAYER",
          "annexe 2 §3.3 ; annexe 1 §4.3")
    banc.reinitialiser()
    base, controle, conf = banc.sable("a05")
    banc.poser_usine(controle, secret="secret-usine-A0003-annule")
    marque = banc.marque_trace()
    banc.agent(base, controle, conf, tours=3)
    tentatives = banc.requetes_depuis(marque, "/enroler")
    r.verifier(len(tentatives) == 3,
               "trois tours = trois tentatives : un 403 d'usine n'est pas terminal",
               tentatives)
    r.verifier(all("-> 403" in t for t in tentatives), "chacune refusée en 403", tentatives)
    etat = lire_json(os.path.join(controle, "etat-agent.json"))
    r.verifier(etat["etat"] == "usine" and etat["code_config_kit"] == "403",
               "etat-agent.json porte l'alerte locale, l'état reste usine", etat)
    r.verifier(os.path.exists(os.path.join(controle, "usine.json")),
               "usine.json conservé — il n'y a rien eu à consommer")
    r.fin("A-05 403 d'enrôlement")

    # =========================================================================
    r.cas("A-18 — 500 sur /enroler : « réponse inattendue », JAMAIS « injoignable »",
          "annexe 2 §3.3 — le premier enrôlement réel (A0003, 17/08/2026) a payé "
          "ce diagnostic : le serveur répondait 500, l'agent concluait « aucune URL "
          "joignable », et l'exploitant cherchait un problème de réseau inexistant")
    banc.reinitialiser()
    base, controle, conf = banc.sable("a18")
    banc.poser_usine(controle)
    banc.pilotage("POST", "/_mock/coupure",
                  {"mode": "erreur_500", "routes": ["/enroler"], "appels": 2})
    marque = banc.marque_trace()
    banc.agent(base, controle, conf, tours=1)
    tentatives = banc.requetes_depuis(marque, "/enroler")
    r.verifier(len(tentatives) >= 1, "le tour a bien tenté l'enrôlement", tentatives)
    etat = lire_json(os.path.join(controle, "etat-agent.json"))
    r.verifier(etat["code_config_kit"] == "500",
               "le CODE reçu est journalisé, pas avalé par un `*) : ;`", etat)
    r.verifier("inattendue" in etat.get("detail", "").lower()
               and "joignable" in etat.get("detail", "").lower(),
               "le détail dit « réponse inattendue » ET que le nœud est joignable", etat)
    r.verifier("aucune URL" not in etat.get("detail", ""),
               "il ne dit SURTOUT PAS « aucune URL joignable » — c'est faux et ça "
               "envoie chercher au mauvais endroit", etat)
    r.verifier(os.path.exists(os.path.join(controle, "usine.json")),
               "usine.json conservé : rien n'a été consommé")
    banc.pilotage("POST", "/_mock/coupure/effacer", {})
    banc.agent(base, controle, conf, tours=1)
    r.verifier(not os.path.exists(os.path.join(controle, "usine.json")),
               "le 500 levé, le tour suivant enrôle — la boucle ne s'est pas arrêtée")
    r.fin("A-18 réponse inattendue")

    # =========================================================================
    r.cas("A-06 — NOMINAL, 200 : les blocs pki/tls/registre, et le témoin EN DERNIER",
          "annexe 2 §3.2 et §3.3 ; invariants 3, 11 ; annexe 1 §4.4")
    base, controle, conf, _ = enroler("a06")
    marque = banc.marque_trace()
    acheve, _ = banc.agent(base, controle, conf, tours=1)
    appels = banc.requetes_depuis(marque, "/config-kit")
    r.verifier(appels and "-> 200" in appels[0],
               "le premier re-poll après l'enrôlement est un 200 (il remet pki/tls/registre)",
               appels or acheve.stderr.decode())
    modes_attendus = {
        "pki/ancres.pem": ("644", None),
        "pki/crl.pem": ("644", None),
        "tls/local.crt": ("644", None),
        "tls/local.key": ("640", GID_LECTURE),
        "registre/auth.json": ("600", None),
    }
    for nom, (attendu, groupe) in modes_attendus.items():
        chemin = os.path.join(controle, nom)
        if not r.verifier(os.path.exists(chemin), "%s écrit" % nom):
            continue
        r.verifier(mode(chemin) == attendu, "%s en %s" % (nom, attendu),
                   "obtenu %s" % mode(chemin))
        uid, gid = proprietaire(chemin)
        r.verifier(uid == 0, "%s appartient à root" % nom)
        if groupe is not None:
            r.verifier(gid == groupe, "%s au GID %d" % (nom, groupe), "obtenu %d" % gid)
    r.verifier(proprietaire(os.path.join(controle, "registre/auth.json"))[1] == 0,
               "registre/auth.json reste au groupe root : seul dockerd le lit (invariant 11)")
    auth = lire_json(os.path.join(controle, "registre/auth.json"))
    r.verifier("utilisateur" in auth and "secret" in auth,
               "auth.json porte l'identité du robot Harbor du kit", sorted(auth))
    version = os.stat(os.path.join(controle, "endpoints.version")).st_mtime_ns
    plus_tard = [n for n in modes_attendus
                 if os.stat(os.path.join(controle, n)).st_mtime_ns > version]
    r.verifier(not plus_tard,
               "endpoints.version est écrit EN DERNIER — le témoin après ce qu'il atteste",
               plus_tard)
    r.fin("A-06 re-poll 200")

    # =========================================================================
    r.cas("A-07 — NOMINAL, 304 : le cas courant ne touche RIEN",
          "annexe 2 §3.3 ; annexe 1 §4.4")
    avant = empreintes(controle)
    marque = banc.marque_trace()
    banc.agent(base, controle, conf, tours=1)
    appels = banc.requetes_depuis(marque, "/config-kit")
    r.verifier(appels and "-> 304" in appels[0], "re-poll suivant : 304", appels)
    apres = empreintes(controle)
    # On itère sur la RÉFÉRENCE : un fichier d'état SUPPRIMÉ par un 304 est
    # au moins aussi grave qu'un fichier réécrit, et n'apparaîtrait pas si
    # l'on parcourait l'état d'arrivée.
    touches = [n for n in avant
               if n != "etat-agent.json" and avant.get(n) != apres.get(n)]
    r.verifier(not touches, "aucun fichier d'état réécrit ni supprimé sur un 304", touches)
    r.verifier(lire_json(os.path.join(controle, "etat-agent.json"))["code_config_kit"] == "304",
               "seul etat-agent.json est rafraîchi — « la fraîcheur vaut vie »")
    r.fin("A-07 re-poll 304")

    # =========================================================================
    r.cas("A-08 — `release_cible` : un marqueur, JAMAIS une application",
          "annexe 2, invariant 6 ; annexe 7 §4")
    chemin = os.path.join(controle, "release_cible")
    r.verifier(os.path.exists(chemin) and lire(chemin).strip() == "2026.08.1",
               "release_cible écrite telle qu'annoncée",
               lire(chemin).strip() if os.path.exists(chemin) else "absente")
    r.verifier(mode(chemin) == "644", "release_cible en 644 — l'updater la lit")
    source = lire(os.path.join(os.path.dirname(ICI), "..", "docker", "wg",
                               "agent-enrolement.sh"))
    # Sur le CODE seul : les lignes de commentaire sont retirées, jamais
    # leur marqueur (l'enlever rendrait les commentaires détectables, soit
    # l'inverse de ce qu'on veut).
    code = "\n".join(l for l in source.splitlines() if not l.lstrip().startswith("#"))
    interdits = [m for m in ("docker ", "docker-compose", "compose ", "systemctl", "apt-get")
                 if m in code.replace("dockerd", "")]
    r.verifier(not interdits,
               "l'agent d'enrôlement n'invoque aucun outil de déploiement (invariant 6)",
               interdits)
    r.verifier("iptables" not in code and "ipset" not in code and "nft " not in code,
               "et il n'invoque jamais netfilter (arbitrage Q1)")
    r.fin("A-08 release_cible")

    # =========================================================================
    r.cas("A-09 — 403 sur /config-kit → SUSPENDU ; 200 → reprise",
          "annexe 2 §3.3 et invariant 4 ; annexe 1 §4.4")
    banc.admin("POST", "/kits/A0001/suspendre", {})
    banc.agent(base, controle, conf, tours=1)
    etat = lire_json(os.path.join(controle, "etat-agent.json"))
    r.verifier(etat["etat"] == "suspendu" and etat["code_config_kit"] == "403",
               "un 403 fait basculer en SUSPENDU", etat)
    r.verifier(os.path.exists(os.path.join(conf, "wg0.conf")),
               "rien n'est purgé : le kit ne se débranche jamais tout seul")
    banc.admin("POST", "/kits/A0001/reprendre", {})
    banc.agent(base, controle, conf, tours=1)
    etat = lire_json(os.path.join(controle, "etat-agent.json"))
    r.verifier(etat["etat"] == "enrole",
               "le re-poll ne s'est jamais arrêté : il détecte la reprise (invariant 4)", etat)
    r.fin("A-09 suspension et reprise")

    # =========================================================================
    r.cas("A-10 — 401 → IDENTITE_PERDUE : cadence NOMINALE conservée, rien purgé",
          "annexe 2 §3.3 et invariant 4 (arbitrage N-1)")
    base, controle, conf, _ = enroler("a10")
    banc.agent(base, controle, conf, tours=1)          # 200 : pki/tls/registre
    avant = empreintes(controle)
    with open(os.path.join(controle, "secret_api"), "w") as f:
        f.write("porteur-que-le-serveur-ne-connait-pas")
    banc.agent(base, controle, conf, tours=1)
    etat = lire_json(os.path.join(controle, "etat-agent.json"))
    r.verifier(etat["etat"] == "identite_perdue" and etat["code_config_kit"] == "401",
               "un 401 mène à IDENTITE_PERDUE, jamais à SUSPENDU", etat)
    apres = empreintes(controle)
    touches = [n for n in avant
               if n not in ("etat-agent.json", "secret_api") and avant.get(n) != apres.get(n)]
    r.verifier(not touches, "aucune purge : endpoints, conf et blocs restent en place", touches)

    # La cadence, MESURÉE : trois tours (donc deux attentes) en
    # IDENTITE_PERDUE doivent coûter la période nominale, jamais le ralenti
    # de 24 h. C'est l'invariant 4, et c'est ce que N-1 a tranché.
    #
    # Le repli est neutralisé ici (`localhost` résout) : on mesure des
    # attentes, et un échec de résolution ajouterait à chaque tour un délai
    # qui n'a rien à voir avec la cadence.
    NOMINALE, RALENTI, TOURS = 1, 8, 3
    with open(os.path.join(controle, "repoll.txt"), "w") as f:
        f.write("localhost 127.0.0.1\n")
    _, duree_perdue = banc.agent(base, controle, conf, tours=TOURS,
                                 nominale=NOMINALE, suspendu=RALENTI)
    base2, controle2, conf2, _ = enroler("a10bis", resoluble=True)
    banc.admin("POST", "/kits/A0001/suspendre", {})
    # Un tour de TRANSITION d'abord : on chronomètre trois tours PASSÉS dans
    # l'état, pas la bascule qui y mène — la cadence d'un tour est celle de
    # l'état où il commence.
    banc.agent(base2, controle2, conf2, tours=1)
    _, duree_suspendu = banc.agent(base2, controle2, conf2, tours=TOURS,
                                   nominale=NOMINALE, suspendu=RALENTI)
    r.verifier(lire_json(os.path.join(controle2, "etat-agent.json"))["etat"] == "suspendu",
               "le témoin de comparaison est bien en SUSPENDU")
    # Écart ATTENDU entre les deux séries : (TOURS-1) attentes de différence.
    attendu = (TOURS - 1) * (RALENTI - NOMINALE)
    r.verifier(duree_suspendu - duree_perdue > 0.7 * attendu,
               "IDENTITE_PERDUE bat à la cadence nominale, pas au ralenti de 24 h",
               "perdue=%.1fs suspendu=%.1fs écart attendu≈%ds"
               % (duree_perdue, duree_suspendu, attendu))
    r.fin("A-10 identité perdue")

    # =========================================================================
    r.cas("A-11 — IDENTITE_PERDUE avec l'amorce encore là : on retente l'enrôlement",
          "annexe 2 §3.3, première branche (arbitrages N-1 et Q6)")
    banc.reinitialiser()
    base, controle, conf = banc.sable("a11")
    banc.poser_usine(controle)
    banc.agent(base, controle, conf, tours=1)
    r.verifier(not os.path.exists(os.path.join(controle, "usine.json")), "kit enrôlé")
    # Une carte SD fatiguée : le secret devient illisible. L'amorce, elle,
    # a survécu (l'atelier l'a reposée, ou la suppression avait échoué).
    with open(os.path.join(controle, "secret_api"), "w") as f:
        f.write("")
    banc.poser_usine(controle)
    marque = banc.marque_trace()
    acheve, _ = banc.agent(base, controle, conf, tours=1)
    r.verifier(banc.requetes_depuis(marque, "/enroler"),
               "l'amorce présente ramène à USINE : POST /enroler retenté",
               acheve.stderr.decode()[-400:])
    r.verifier(not os.path.exists(os.path.join(controle, "usine.json")),
               "et le rejeu aboutit — usine.json de nouveau supprimé")
    r.verifier(os.path.getsize(os.path.join(controle, "secret_api")) > 0,
               "un secret_api neuf a été remis (l'ancien est invalidé côté serveur)")
    r.fin("A-11 identité perdue avec amorce")

    # =========================================================================
    r.cas("A-12 — IDENTITE_PERDUE sans amorce ni porteur : AUCUNE requête n'est émise",
          "annexe 2 §3.3, troisième branche ; invariant 4 (arbitrage Q6)")
    os.remove(os.path.join(controle, "secret_api"))
    marque = banc.marque_trace()
    acheve, _ = banc.agent(base, controle, conf, tours=2)
    emises = banc.requetes_depuis(marque, "/config-kit") + banc.requetes_depuis(marque, "/enroler")
    r.verifier(not emises,
               "deux battements, zéro requête : une requête sans porteur ne peut pas réussir",
               emises)
    etat = lire_json(os.path.join(controle, "etat-agent.json"))
    r.verifier(etat["etat"] == "identite_perdue",
               "l'état est signalé localement pour l'intervention sur place", etat)
    r.verifier("relecture au prochain battement" in acheve.stderr.decode(),
               "et ce qui est retenté est la LECTURE du fichier, pas un appel")
    r.fin("A-12 identité perdue sans porteur")

    # =========================================================================
    r.cas("A-13 — repli sur l'IP : le nom est conservé, aucune empreinte épinglée",
          "annexe 2 §3.3 (arbitrage Q3) ; annexe 1 §5.2")
    source = lire(os.path.join(os.path.dirname(ICI), "..", "docker", "wg",
                               "agent-enrolement.sh"))
    r.verifier("empreinte_tls" not in source and "--pinnedpubkey" not in source,
               "l'agent d'enrôlement n'épingle rien, et ne lit pas empreinte_tls")
    r.verifier(" -k " not in source and "--insecure" not in source,
               "et il ne désactive jamais la vérification")
    port_tls = banc.demarrer_tls()
    if not port_tls:
        r.sauter("A-13 repli sur l'IP", "openssl absent — le volet TLS n'est pas rejouable")
    else:
        # Le repli, en TLS RÉEL. Le nom ne résout pas ; le certificat servi
        # porte ce nom et rien d'autre — pas de SAN sur l'IP. Un agent
        # d'enrôlement qui joindrait l'IP en réécrivant l'URL verrait donc
        # la vérification échouer, et n'enrôlerait rien.
        banc.reinitialiser()
        base, controle, conf = banc.sable("a13")
        banc.poser_usine(controle, tls=port_tls)
        acheve, _ = banc.agent(base, controle, conf, tours=1,
                               tls=port_tls, ca=banc.tls_ca)
        traces = acheve.stderr.decode()
        r.verifier(not os.path.exists(os.path.join(controle, "usine.json")),
                   "l'enrôlement aboutit en HTTPS alors que le nom NE RÉSOUT PAS : "
                   "l'IP est jointe, le nom est conservé (SNI et chaîne)", traces[-500:])
        r.verifier("repli sur 127.0.0.1, nom conservé" in traces,
                   "et c'est bien le repli qui a servi", traces[-500:])
        marque = banc.marque_trace()
        acheve, _ = banc.agent(base, controle, conf, tours=1,
                               tls=port_tls, ca=banc.tls_ca)
        r.verifier(banc.requetes_depuis(marque, "/config-kit"),
                   "le re-poll emprunte le même chemin depuis repoll.txt (couples L4)")

        # Le NÉGATIF, sans lequel tout ce qui précède passerait avec `-k` :
        # la même requête, une ancre qui n'est pas celle du certificat.
        banc.reinitialiser()
        base2, controle2, conf2 = banc.sable("a13-ca-etrangere")
        banc.poser_usine(controle2, tls=port_tls)
        acheve, _ = banc.agent(base2, controle2, conf2, tours=1,
                               tls=port_tls, ca=banc.tls_ca_etrangere)
        r.verifier(os.path.exists(os.path.join(controle2, "usine.json")),
                   "avec une CA étrangère, l'enrôlement ÉCHOUE — la vérification "
                   "de chaîne est réelle, ce n'est pas un tunnel en clair déguisé",
                   acheve.stderr.decode()[-300:])
        r.verifier(not os.path.exists(os.path.join(controle2, "secret_api")),
                   "et rien n'a été écrit")

        # La voie normale : un nom qui résout n'emprunte aucun repli.
        banc.reinitialiser()
        base3, controle3, conf3 = banc.sable("a13-direct")
        banc.poser_usine(controle3, resoluble=True)
        acheve, _ = banc.agent(base3, controle3, conf3, tours=1)
        r.verifier("repli sur" not in acheve.stderr.decode(),
                   "un nom qui résout est joint directement — le repli est l'exception")
        r.fin("A-13 repli sur l'IP")

    # =========================================================================
    r.cas("A-14 — rotation de la clé de passerelles : syncconf, jamais down/up",
          "arch. §11.4 ; annexe 2 §3.5 ; annexe 1 §4.4")
    base, controle, conf, _ = enroler("a14")
    banc.agent(base, controle, conf, tours=1)          # 200 initial
    open(os.path.join(base, "wg0-montee"), "w").close()   # wg0 est montée
    banc.pilotage("POST", "/_mock/passerelles/rotation",
                  {"cle_publique": "Q0xFLVBBUlRBR0VFLUFQUkVTLVJPVEFUSU9OAAAAAAA=",
                   "port": 51830})
    banc.agent(base, controle, conf, tours=1)
    r.verifier(lire(os.path.join(controle, "port")).strip() == "51830",
               "le fichier `port` porte 51830 — le watchdog le relit (arbitrage N4)",
               lire(os.path.join(controle, "port")).strip())
    conf_wg0 = lire(os.path.join(conf, "wg0.conf"))
    r.verifier("Q0xFLVBBUlRBR0VFLUFQUkVTLVJPVEFUSU9OAAAAAAA=" in conf_wg0,
               "le [Peer] porte la nouvelle clé partagée")
    r.verifier(":51830" in conf_wg0, "et le nouveau port")
    appels = banc.appels_wg(base)
    r.verifier(any(a.startswith("wg syncconf") for a in appels),
               "la conf est appliquée par `wg syncconf` (à chaud)", appels)
    r.verifier(not any("wg-quick down" in a or "wg-quick up" in a for a in appels),
               "aucun down/up : la rotation ne coupe pas le tunnel", appels)
    r.fin("A-14 rotation de clé")

    # =========================================================================
    r.cas("A-15 — 500, temporisation, API morte : on garde tout et on retente",
          "annexe 2 §3.3 ; annexe 3, invariant 6 (« un 401 ne purge jamais »)")
    base, controle, conf, _ = enroler("a15")
    banc.agent(base, controle, conf, tours=1)
    reference = empreintes(controle)
    for mode_coupure, corps in (
            ("erreur_500", {"mode": "erreur_500", "routes": ["/config-kit"], "appels": 1}),
            ("temporisation", {"mode": "temporisation", "routes": ["/config-kit"],
                               "appels": 1, "duree_s": 8}),
            ("ecoute_fermee", {"mode": "ecoute_fermee", "duree_s": 3})):
        banc.pilotage("POST", "/_mock/coupure", corps)
        if mode_coupure == "ecoute_fermee":
            # La fermeture est différée (le mock laisse partir sa réponse de
            # pilotage) : sans cette attente, l'agent d'enrôlement tournerait
            # AVANT la coupure — un cas vert qui n'aurait rien coupé.
            r.verifier(banc.attendre_mock_ferme(),
                       "ecoute_fermee : les écoutes sont effectivement fermées")
        acheve, _ = banc.agent(base, controle, conf, tours=1)
        apres = empreintes(controle)
        touches = [n for n in reference
                   if n != "etat-agent.json" and reference.get(n) != apres.get(n)]
        r.verifier(not touches, "%s : aucun fichier d'état modifié" % mode_coupure, touches)
        etat = lire_json(os.path.join(controle, "etat-agent.json"))
        r.verifier(etat["etat"] == "enrole",
                   "%s : l'état est conservé, ce n'est ni une suspension ni une perte d'identité"
                   % mode_coupure, etat)
        if mode_coupure == "ecoute_fermee":
            r.verifier(banc.attendre_mock(), "ecoute_fermee : les écoutes se rouvrent seules")
        banc.pilotage("POST", "/_mock/coupure/effacer", {})
    banc.agent(base, controle, conf, tours=1)
    r.verifier(lire_json(os.path.join(controle, "etat-agent.json"))["code_config_kit"] in ("200", "304"),
               "les coupures levées, le re-poll repart tout seul")
    r.fin("A-15 coupures")

    # =========================================================================
    r.cas("A-16 — les cadences par défaut sont celles du corpus",
          "annexe 2 §3.3 ; invariant 4")
    source = lire(os.path.join(os.path.dirname(ICI), "..", "docker", "wg",
                               "agent-enrolement.sh"))
    for libelle, attendu in (("re-poll nominal (6 h)", "AGENT_PERIODE_NOMINALE_S:-21600"),
                             ("ralenti suspendu (24 h)", "AGENT_PERIODE_SUSPENDU_S:-86400"),
                             ("backoff bas (1 min)", "AGENT_BACKOFF_MIN_S:-60"),
                             ("backoff haut (15 min)", "AGENT_BACKOFF_MAX_S:-900")):
        r.verifier(attendu in source, "%s : défaut conforme" % libelle, attendu)
    r.verifier("AGENT_TOURS:-0" in source,
               "sans borne d'exécution, l'agent d'enrôlement tourne SANS FIN — le régime du kit")
    r.fin("A-16 cadences et invariant 6")

    # =========================================================================
    r.cas("A-17 — l'ordre des écritures : usine.json ne part qu'en DERNIER",
          "annexe 2 §3.3 et invariant 2 (arbitrage Q2)")
    # Le point de non-retour ne se vérifie pas sur l'état final — il se
    # vérifie en COUPANT la séquence. La doublure `mv` fait échouer la
    # publication d'un fichier désigné : `usine.json` doit alors survivre,
    # quel que soit l'endroit de la coupure.
    for interrompu, encore_absent in (("secret_api", "wg0.conf"),
                                      ("endpoints.version", None)):
        banc.reinitialiser()
        base, controle, conf = banc.sable("a17-" + interrompu)
        banc.poser_usine(controle)
        acheve, _ = banc.agent(base, controle, conf, tours=1, mv_echoue=interrompu)
        r.verifier(os.path.exists(os.path.join(controle, "usine.json")),
                   "écriture de %s interrompue : usine.json est CONSERVÉ" % interrompu,
                   acheve.stderr.decode()[-300:])
        if encore_absent:
            r.verifier(not os.path.exists(os.path.join(conf, encore_absent)),
                       "et la séquence s'est arrêtée là (%s pas écrit)" % encore_absent)
        # La coupure levée, le rejeu aboutit : la reprise est idempotente.
        acheve, _ = banc.agent(base, controle, conf, tours=1)
        r.verifier(not os.path.exists(os.path.join(controle, "usine.json")),
                   "au tour suivant, l'enrôlement aboutit et usine.json part")

    # L'ordre INTERNE de la séquence, par les dates de publication.
    ordre = ["secret_api", "endpoints.txt", "port", "repoll.txt",
             "applicatif.json", "domaines.json", "endpoints.version"]
    dates = [(n, os.stat(os.path.join(controle, n)).st_mtime_ns) for n in ordre]
    desordre = [dates[i][0] for i in range(1, len(dates))
                if dates[i][1] < dates[i - 1][1]]
    r.verifier(not desordre,
               "les fichiers sont publiés dans l'ordre normatif du §3.3", desordre)
    r.verifier(os.stat(os.path.join(conf, "wg0.conf")).st_mtime_ns >= dates[0][1],
               "wg0.conf est écrite après secret_api")
    r.fin("A-17 ordre des écritures")

finally:
    banc.arreter()

sortir(r)
