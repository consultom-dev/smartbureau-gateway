# =============================================================================
# wg-core-ctl — surface de contrôle du peer wg-core (arbitrages Q17, Q20).
#
# Même base Debian épinglée que les autres images : levier « bases communes »
# de l'annexe 7 §5. Pas de tag mobile (annexe 7 §8, invariants 1 et 4).
#
# `python3` et rien d'autre : la surface n'utilise que la bibliothèque
# standard (http.server, json, base64, ipaddress). Aucune dépendance à
# épingler, aucun avis de sécurité à suivre — comme `parefeu-console`.
# (PAS `python3-minimal` : sur Debian il n'embarque qu'un SOUS-ENSEMBLE de la
# stdlib ; on reste sur `python3` complet, même leçon que parefeu-console.)
#
# AUCUN privilège, AUCUN cap, AUCUN accès réseau hôte : ce conteneur est
# bridgé et n'écrit qu'un fichier (l'état désiré des peers) sur le volume
# partagé `wg-core-peers`. C'est `wg-core` (rôle serveur de l'image `wg`)
# qui réconcilie ce fichier sur `wg0` (Q20).
# =============================================================================
ARG BASE=debian:12-slim
FROM ${BASE}

RUN apt-get update \
 && apt-get install --no-install-recommends -y python3 \
 && rm -rf /var/lib/apt/lists/*

COPY wg_core_ctl.py /usr/local/lib/wg-core-ctl/wg_core_ctl.py

# Le volume `wg-core-peers` est MONTÉ par le compose (§8) — pas un chemin
# créé ici : le monter manquant, la première écriture crée l'arborescence.
ENV WG_CORE_CTL_ETAT=/etc/wg-core-peers/peers.json

# « Sans privilège » se joue au compose (§8) : aucun `cap_add`, pas de netns
# hôte, bridgé — et `cap_drop: [ALL]`. Pas d'`USER nobody` ici : le volume
# `wg-core-peers` est root, et un utilisateur non root n'y écrirait pas
# (même écueil que le volume de `sante`/`parefeu`). Le confinement vient des
# caps retirés, pas de l'uid.
ENTRYPOINT ["python3", "/usr/local/lib/wg-core-ctl/wg_core_ctl.py"]
