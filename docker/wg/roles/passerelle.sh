#!/bin/sh
# =============================================================================
# Rôle PASSERELLE — les interfaces, puis les RÈGLES (annexe 3 §3.2).
#
#   wg-kits : clé PARTAGÉE de la flotte (tirée de Vault, montée en 600 —
#             JAMAIS générée ici), Address 10.200.0.0/16 (la route de
#             retour vers les kits), ListenPort 51820. Sa table de peers
#             est posée de l'EXTÉRIEUR par wg-agent (lot 4) : ce conteneur
#             n'a aucun interlocuteur applicatif et ne décide de rien.
#   wg-core : clé PROPRE au nœud, générée LOCALEMENT au premier démarrage
#             (annexe 3 §2.4) — elle n'est partagée avec personne, seule sa
#             publique part à la déclaration (§6.1, fichier wg-core.pub).
#             Address 10.100.0.X/32, un seul peer : le serveur :51821.
#             Aucun port ouvert VERS wg-core : la passerelle initie.
#
# Rotation (annexe 3 §6.4) : une seconde interface wg-kits2 (port 51830)
# vivra des semaines à côté de wg-kits — la forme « une interface = une
# conf = un montage » posée ici la rend possible sans réécriture.
# =============================================================================
set -eu
. /usr/local/lib/wg/roles/commun.sh

# Premier démarrage : la paire wg-core naît ici, et la conf est rendue
# depuis l'environnement (l'endpoint du serveur et l'adresse /32 de CE nœud
# viennent du provisionnement — lot 4 ; la maquette du lot 2 les fournit).
if [ ! -f "$WG_CONF/wg-core.conf" ]; then
  : "${WG_CORE_ADRESSE:?wg-core.conf absent et WG_CORE_ADRESSE non défini (10.100.0.X/32)}"
  : "${SERVEUR_ENDPOINT:?wg-core.conf absent et SERVEUR_ENDPOINT non défini (ip:51821)}"
  : "${SERVEUR_CLE_PUBLIQUE:?wg-core.conf absent et SERVEUR_CLE_PUBLIQUE non défini}"
  umask 077
  wg genkey > "$WG_CONF/wg-core.key"
  wg pubkey < "$WG_CONF/wg-core.key" > "$WG_CONF/wg-core.pub"
  cat > "$WG_CONF/wg-core.conf" <<CONF
[Interface]
Address    = ${WG_CORE_ADRESSE}
PrivateKey = $(cat "$WG_CONF/wg-core.key")

[Peer]
PublicKey           = ${SERVEUR_CLE_PUBLIQUE}
Endpoint            = ${SERVEUR_ENDPOINT}
AllowedIPs          = 10.100.0.0/24
PersistentKeepalive = 25
CONF
  umask 022
  journal "paire wg-core née (premier démarrage, annexe 3 §2.4) — publique dans wg-core.pub, à déclarer (§6.1)"
fi

NETFILTER="/usr/local/lib/wg/netfilter-passerelle.sh"
PIDS=""

arreter() {
  for p in $PIDS; do kill -TERM "$p" 2>/dev/null || true; done
  # ATTENDRE que la boucle ait retiré SES règles, sans le supposer : les
  # descendre d'abord laisserait des règles orphelines référençant des
  # interfaces disparues, que le prochain démarrage retrouverait sans les
  # reconnaître. On attend qu'elle ait rendu la main, jusqu'à 5 s — au-delà,
  # `compose stop` nous tuerait de toute façon, et des règles orphelines
  # valent mieux qu'un arrêt qui ne finit pas.
  _tours=0
  while [ -n "$PIDS" ] && [ "$_tours" -lt 10 ]; do
    _encore=0
    for p in $PIDS; do kill -0 "$p" 2>/dev/null && _encore=1; done
    [ "$_encore" = 0 ] && break
    _tours=$((_tours + 1))
    sleep 0.5
  done
  descendre wg-core wg-kits
  exit 0
}
trap arreter TERM INT

monter wg-kits
monter wg-core
journal "wg-kits (51820) et wg-core montées"

# Les règles APRÈS les interfaces : `-i wg-kits` sur une interface absente
# est refusé par netfilter. La boucle réaffirme toutes les 30 s — docker et
# les redémarrages repoussent les règles — et retire tout à l'arrêt.
if [ -x "$NETFILTER" ]; then
  "$NETFILTER" --boucle &
  PIDS="$PIDS $!"
else
  journal "ATTENTION : $NETFILTER absent — la passerelle n'a AUCUNE règle"
fi

tenir wg-kits wg-core
