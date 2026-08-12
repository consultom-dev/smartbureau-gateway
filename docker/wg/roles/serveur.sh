#!/bin/sh
# =============================================================================
# Rôle SERVEUR — le plus court des trois (arch. §4.2).
#
# wg0 : Address 10.100.0.1/24, ListenPort 51821, un [Peer] par passerelle
# (AllowedIPs = 10.100.0.X/32) et un pour la VM usine (10.100.0.100/32,
# annexe 7 §7). La conf est PROVISIONNÉE (montée), jamais écrite ici.
#
# AUCUN forwarding, AUCUN NAT : le serveur est une FEUILLE — les passerelles
# sont les seuls nœuds qui routent. Ce script ne pose donc rien d'autre que
# l'interface, et c'est un invariant, pas une paresse.
#
# Race de bind ASSUMÉE (arch. §4.2) : `gestion` peut binder 10.100.0.1 avant
# que wg0 ait posé l'adresse ; le restart converge. Ne pas « réparer » par
# un depends_on.
# =============================================================================
set -eu
. /usr/local/lib/wg/roles/commun.sh

trap 'descendre wg0; exit 0' TERM INT
monter wg0
echo "wg(serveur): wg0 montée — 10.100.0.1/24, écoute 51821 (arch. §4.2)" >&2
tenir wg0
