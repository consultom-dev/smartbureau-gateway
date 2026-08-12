#!/bin/sh
# =============================================================================
# Image `wg` — l'aiguillage des trois rôles (annexe 7 §1 ; annexe 3 §3 ;
# annexe 2 §3). WG_ROLE=serveur|passerelle|kit, et rien d'autre : un rôle
# inconnu est un refus bruyant, jamais un défaut silencieux.
#
# Deux gardes communes AVANT tout rôle :
#   1. backend netfilter nf_tables (piège 9) — même le rôle kit, qui
#      n'invoque jamais netfilter (arbitrage Q1), refuse une image mal
#      construite : le défaut se verrait au pire moment, sur une passerelle ;
#   2. trap de retrait : les interfaces posées sont redescendues à l'arrêt —
#      un conteneur wg mort ne laisse pas d'interface orpheline en netns hôte.
# =============================================================================
set -eu

ROLES="/usr/local/lib/wg/roles"

: "${WG_ROLE:?WG_ROLE non défini : serveur, passerelle ou kit (annexe 7 §1)}"
case "$WG_ROLE" in
  serveur|passerelle|kit) : ;;
  *) echo "wg: rôle inconnu « $WG_ROLE » — serveur, passerelle ou kit" >&2; exit 1 ;;
esac

# Piège 9 : en backend legacy, les règles netfilter seraient posées dans une
# table que PERSONNE ne lit — muettes, et tous les tests faussement verts.
# Formulation FAIL-SAFE : on exige la PRÉSENCE de « nf_tables », on ne refuse
# pas seulement « legacy » — une sortie vide (iptables muet) doit échouer,
# pas passer.
if ! iptables --version 2>/dev/null | grep -q nf_tables; then
  echo "wg: backend netfilter « $(iptables --version 2>&1) » — nf_tables exigé (piège 9)" >&2
  exit 1
fi

exec sh "$ROLES/$WG_ROLE.sh"
