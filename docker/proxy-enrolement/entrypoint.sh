#!/bin/sh
# =============================================================================
# Rend le modèle nginx et démarre. Deux substitutions, pas une de plus :
# le nom public du nœud et l'hôte du plan de contrôle.
#
# REFUS BRUYANT si le certificat manque : un proxy d'enrôlement qui démarre
# sans son wildcard écoute sans pouvoir servir, et ferme l'enrôlement comme
# le re-poll de toute la flotte servie — en ayant l'air vivant
# (annexe 3, invariant 10).
# =============================================================================
set -eu

NOM="${NOM:?NOM non défini — gw-NN.gateway.<domaine>.tld}"
API="${API:?API non définie — https://api.server.<domaine>.tld}"
API_HOTE="$(printf '%s' "$API" | sed -e 's,^[a-z][a-z]*://,,' -e 's,[:/].*$,,')"
TLS="${TLS_DIR:-/etc/proxy/tls}"

for f in "$TLS/gateway.crt" "$TLS/gateway.key"; do
  [ -r "$f" ] || { echo "proxy-enrolement: $f absent — le wildcard *.gateway se tire de Vault (annexe 3 §2.4)" >&2; exit 1; }
done

for modele in /etc/nginx/nginx.conf.modele:/etc/nginx/nginx.conf \
              /etc/nginx/relais.conf.modele:/etc/nginx/relais.conf; do
  src="${modele%%:*}"; dst="${modele##*:}"
  sed -e "s/NOM_PUBLIC/$NOM/g" -e "s/API_HOTE/$API_HOTE/g" "$src" > "$dst"
done

echo "proxy-enrolement: $NOM → $API_HOTE (deux routes, tout le reste en 404)" >&2
exec nginx -g 'daemon off;'
