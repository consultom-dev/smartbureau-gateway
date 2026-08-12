#!/bin/sh
# =============================================================================
# La BOUCLE DE MARQUEURS du kit — `etat.json`, toutes les 60 s
# (annexe 2 §3.2 ; lu par `sante`, §4).
#
# Elle vit ici, dans le conteneur `wg` du rôle kit, parce qu'elle est le seul
# processus à voir à la fois les DEUX sources de l'état d'un kit :
#
#   - l'interface, par `wg show` — endpoint courant et dernier handshake ;
#     elle n'est visible que du netns hôte, et `wireguard-tools` n'est que
#     dans cette image ;
#   - `etat-agent.json`, écrit par l'agent d'enrôlement à son propre rythme
#     (6 h en nominal), dont elle **recopie** l'état et le dernier code.
#
# POURQUOI UNE BOUCLE À PART, et pas l'agent d'enrôlement qui écrirait
# `etat.json` lui-même : les deux cadences n'ont rien à voir. Il bat toutes
# les 6 h — un `etat.json` vieux de six heures ne dit plus rien de la
# vivacité du tunnel, et `sante` pousse, lui, toutes les 15 min. « Un fichier
# atomique, la fraîcheur vaut vie » (§3.2).
#
# UN SEUL PROPRIÉTAIRE : `etat.json` est à cette boucle, `etat-agent.json` à
# l'agent d'enrôlement. Deux écrivains atomiques sur un même fichier ne se
# complètent pas — chaque `rename` publie l'image du dernier et efface les
# champs de l'autre. C'est la règle « un seul propriétaire » du kit, la même
# qui gouverne les règles netfilter.
#
# Elle n'écrit RIEN d'autre, ne décide RIEN, et ne parle à personne : c'est un
# observateur. Pas de `set -e`, même doctrine que ses deux voisins.
# =============================================================================
set -u

ICI="$(cd "$(dirname "$0")" && pwd)"
. "$ICI/roles/commun.sh"

WG_ROLE="${WG_ROLE:-kit}"
IFACE="${MARQUEURS_IFACE:-wg0}"
ETAT="$CONTROLE/etat.json"
ETAT_AGENT="$CONTROLE/etat-agent.json"
PERIODE="${MARQUEURS_PERIODE_S:-60}"
TOURS_MAX="${MARQUEURS_TOURS:-0}"       # 0 = sans fin, le régime du kit

journal() { printf 'wg(marqueurs): %s\n' "$*" >&2; }

battre() {
  _etat=usine
  _code="-"
  if lisible "$ETAT_AGENT"; then
    _etat="$(jq -r '.etat // "usine"' "$ETAT_AGENT" 2>/dev/null)"
    _code="$(jq -r '.code_config_kit // "-"' "$ETAT_AGENT" 2>/dev/null)"
  fi
  # Un `etat-agent.json` illisible ne se devine pas : on le dit, plutôt que
  # de publier un état inventé que `sante` remonterait comme une vérité.
  case "${_etat:-}" in
    usine|enrole|suspendu|identite_perdue) : ;;
    *) _etat=inconnu ;;
  esac

  _endpoint=""
  _handshake=0
  if ip link show "$IFACE" >/dev/null 2>&1; then
    _endpoint="$(wg show "$IFACE" endpoints 2>/dev/null | awk 'NR==1{print $2}')"
    _handshake="$(wg show "$IFACE" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')"
  fi
  case "${_handshake:-}" in ''|*[!0-9]*) _handshake=0 ;; esac

  # `poser_valeur` et non `poser` : un `jq` en échec produirait un flux VIDE,
  # et `poser` publierait consciencieusement un `etat.json` de zéro octet —
  # `sante` remonterait alors l'absence d'état comme un état. Une valeur vide
  # ne remplace jamais un fichier d'état (§3.2).
  _rendu="$(jq -n --arg etat "$_etat" --arg code "$_code" \
        --arg endpoint "${_endpoint:-}" --argjson handshake "$_handshake" \
        --arg horodatage "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     '{etat: $etat, code_config_kit: $code, endpoint: $endpoint,
       dernier_handshake: $handshake, horodatage: $horodatage}')" || return 1
  poser_valeur "$_rendu" "$ETAT" 644
}

journal "démarrage — période ${PERIODE}s, $ETAT (annexe 2 §3.2)"
tour=0
while :; do
  tour=$((tour + 1))
  battre || journal "battement manqué — $ETAT conservé en l'état"
  if [ "$TOURS_MAX" -ne 0 ] && [ "$tour" -ge "$TOURS_MAX" ]; then break; fi
  sleep "$PERIODE"
done
journal "arrêt après $tour tour(s)"
