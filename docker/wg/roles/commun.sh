# =============================================================================
# Socle commun des trois rôles — sourcé, jamais exécuté.
#
# La forme partagée : monter des interfaces wg, les tenir, les REDESCENDRE à
# l'arrêt (un conteneur wg mort ne laisse pas d'interface orpheline dans le
# netns hôte), et mourir BRUYAMMENT si une interface tombe — c'est la
# politique de redémarrage du compose qui relance, jamais une boucle interne
# qui masquerait un crash-loop (même doctrine que freeradius, lot 5b).
# =============================================================================

WG_CONF="${WG_CONF:-/etc/wireguard}"

monter() { # $1 nom d'interface — la conf DOIT exister
  [ -f "$WG_CONF/$1.conf" ] || {
    echo "wg($WG_ROLE): $WG_CONF/$1.conf absent — rien à monter" >&2
    return 1
  }
  # Idempotent : un restart de conteneur retrouve l'interface déjà posée
  # dans le netns hôte — la re-poser serait un échec, pas une convergence.
  # `wg syncconf` (jamais down/up) : la resynchronisation ne coupe pas le
  # tunnel (annexe 2 §3.5, même exigence pour la rotation).
  if ip link show "$1" >/dev/null 2>&1; then
    echo "wg($WG_ROLE): $1 déjà montée — resynchronisation de la conf" >&2
    strip="/tmp/$1.strip.conf"                # POSIX sh : pas de <(…)
    wg-quick strip "$WG_CONF/$1.conf" > "$strip"
    wg syncconf "$1" "$strip"
    rm -f "$strip"
  else
    wg-quick up "$WG_CONF/$1.conf"
  fi
}

descendre() { # $* interfaces, dans l'ordre donné
  for iface in "$@"; do
    wg-quick down "$WG_CONF/$iface.conf" 2>/dev/null \
      || ip link del "$iface" 2>/dev/null || true
  done
}

tenir() { # $* interfaces à surveiller — mort bruyante si l'une disparaît
  while :; do
    sleep 15
    for iface in "$@"; do
      ip link show "$iface" >/dev/null 2>&1 || {
        echo "wg($WG_ROLE): $iface a disparu — arrêt (le compose relance)" >&2
        return 1
      }
    done
  done
}
