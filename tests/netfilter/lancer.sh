#!/usr/bin/env bash
# =============================================================================
# Lance les cas d'invariants netfilter de CE dépôt (P-nn, lot 4).
#
# Décision R3 (10/08/2026) : les cas appartiennent au dépôt qui détient le
# script testé — ils vivent donc ici, dans `tests/netfilter/cas/`. Le
# GABARIT, lui, vit dans `smartbureau-server/outillage/tests-netfilter/` et
# s'épingle par condensat, comme le contrat OpenAPI (`contrats.epingle`).
#
# Développement : poser SMARTBUREAU_SERVER sur une copie locale du dépôt.
# =============================================================================
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVEUR="${SMARTBUREAU_SERVER:-$RACINE/.gabarit}"
LANCEUR="$SERVEUR/outillage/tests-netfilter/lancer.sh"

if [ ! -x "$LANCEUR" ]; then
  cat >&2 <<MSG
gabarit de tests introuvable : $LANCEUR

Il vit dans smartbureau-server et s'épingle par condensat (R3). Deux voies :
  - développement : SMARTBUREAU_SERVER=/chemin/vers/smartbureau-server $0
  - intégration   : outillage/recuperer-contrat.sh récupère aussi le gabarit
MSG
  exit 66
fi

exec "$LANCEUR" --cas-dir "$RACINE/tests/netfilter/cas" --sujet "$RACINE" "$@"
