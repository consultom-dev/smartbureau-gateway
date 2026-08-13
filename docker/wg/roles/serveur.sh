#!/bin/sh
# =============================================================================
# Rôle SERVEUR — le plus court des trois pour l'interface (arch. §4.2).
#
# wg0 : Address 10.100.0.1/24, ListenPort 51821, un [Peer] STATIQUE pour la
# VM usine (10.100.0.100/32, annexe 7 §7). La conf est PROVISIONNÉE (montée),
# jamais écrite ici.
#
# Les peers de PASSERELLE, eux, sont DYNAMIQUES : l'app les pose et les
# retire (arbitrages D4/Q17). Ce rôle porte donc l'APPLICATEUR (Q20) — il
# réconcilie sur wg0 l'état désiré que wg-core-ctl écrit dans un fichier.
# C'est le seul processus à voir wg0 (netns hôte) ; la surface HTTP, bridgée,
# ne fait qu'écrire le fichier. Voir serveur-peers.sh.
#
# AUCUN forwarding, AUCUN NAT : le serveur est une FEUILLE — les passerelles
# sont les seuls nœuds qui routent. Poser un peer n'est PAS router : c'est
# appliquer une décision prise ailleurs (annexe 3 §4.2), exactement comme
# l'agent de passerelle sur wg-kits. L'invariant « feuille » tient.
#
# Race de bind ASSUMÉE (arch. §4.2) : `gestion` peut binder 10.100.0.1 avant
# que wg0 ait posé l'adresse ; le restart converge. Ne pas « réparer » par
# un depends_on.
# =============================================================================
set -eu
. /usr/local/lib/wg/roles/commun.sh
. /usr/local/lib/wg/roles/serveur-peers.sh

_applicateur=""
_arret() {
  if [ -n "$_applicateur" ]; then kill "$_applicateur" 2>/dev/null || true; fi
  descendre wg0
  exit 0
}
trap _arret TERM INT

monter wg0
journal "wg0 montée — 10.100.0.1/24, écoute 51821 (arch. §4.2)"

# L'applicateur du peer wg-core (Q20), en tâche de fond. Couplage lâche :
# peers.json absent ou wg0 pas encore là → il attend, il ne casse rien.
reconcilier_en_boucle wg0 &
_applicateur=$!

# `tenir` garde wg0 et meurt bruyamment si elle disparaît (le compose
# relance). À son retour, on arrête aussi l'applicateur — pas d'orphelin.
tenir wg0 || :
kill "$_applicateur" 2>/dev/null || true
