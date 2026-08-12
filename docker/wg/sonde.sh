#!/bin/sh
# =============================================================================
# Sonde de santé de la PASSERELLE (annexe 3 §3.3).
#
#   wg show wg-core latest-handshakes  →  handshake de moins de 180 s
#   ET  le DROP wg-kits → wg-kits est en place
#
# DEUX conditions, et c'est le point : une passerelle qui a perdu wg-core
# est inutile aux kits — leur watchdog les fera basculer (arch. §7), et la
# sonde le rend visible AVANT qu'ils ne partent. Une passerelle qui a perdu
# son isolation, elle, est pire qu'inutile : elle relaie les kits entre eux.
# Un healthcheck qui ne regarderait que le tunnel laisserait passer le
# second cas sans un mot.
#
# Rendu : 0 (saine) ou 1 (à sortir du service). Aucun effet de bord — une
# sonde qui répare masque la panne qu'elle est chargée de dire.
# =============================================================================
set -u

IFACE_CORE="${IFACE_CORE:-wg-core}"
IFACE_KITS="${IFACE_KITS:-wg-kits}"
FRAICHEUR="${SONDE_FRAICHEUR_S:-180}"

echec() { printf 'wg(sonde): %s\n' "$*" >&2; exit 1; }

wg show "$IFACE_CORE" latest-handshakes 2>/dev/null \
  | awk -v limite="$FRAICHEUR" '
      { vu = 1; if ($2 > 0 && systime() - $2 < limite) frais = 1 }
      END { exit (vu && frais) ? 0 : 1 }' \
  || echec "$IFACE_CORE : aucun handshake de moins de ${FRAICHEUR}s — le tunnel cœur est mort"

iptables -w 5 -C FORWARD -i "$IFACE_KITS" -o "$IFACE_KITS" -j DROP 2>/dev/null \
  || echec "le DROP $IFACE_KITS → $IFACE_KITS est ABSENT — la passerelle relaierait les kits entre eux (invariant 2)"

exit 0
