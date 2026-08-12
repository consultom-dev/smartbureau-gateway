#!/bin/sh
# =============================================================================
# Le WATCHDOG du kit — bascule d'endpoint (annexe 2 §3.4 ; arch. §6.2, §7).
#
# Toutes les 30 s : `ping -c3 -W2 10.100.0.1`. En échec, il commute le peer
# de wg0 sur l'endpoint suivant d'`endpoints.txt`. C'est tout, et c'est
# volontairement tout.
#
# TROIS PROPRIÉTÉS QU'IL NE FAUT PAS LUI RETIRER :
#
#   1. **Le test porte sur le SERVEUR, pas sur le handshake** (arch. §6.2) :
#      une passerelle peut répondre en WireGuard et ne plus router. Le ping
#      part du netns hôte — trafic local, hors `FORWARD` — donc il fonctionne
#      `parefeu` absent : la santé du tunnel et l'autorisation de l'emprunter
#      sont deux choses distinctes.
#   2. **Il ne dépend que de fichiers locaux** (annexe 2, invariant 5) :
#      `endpoints.txt` pour l'adresse, `port` pour le port. Aucun résolveur —
#      le tunnel doit pouvoir remonter DNS cassé —, et aucun processus : la
#      bascule fonctionne **agent d'enrôlement mort**. C'est le critère de
#      fini 3 du lot 2, et c'est ce qui rend un kit réparable sans réseau.
#   3. **Il relit le port à CHAQUE commutation** (arbitrage N4) : pendant une
#      rotation de clé de passerelles, le port courant est 51830 et non 51820
#      (arch. §11.4). Un watchdog qui le mémorise rebascule sur l'ancien port
#      au premier échec — au pire moment, puisque la rotation est justement
#      une période d'instabilité.
#
# La clé publique du peer vient de `wg show`, jamais d'un fichier ni d'une
# variable (arbitrage Q7) : l'interface est la source de vérité, et c'est ce
# qui laisse le watchdog juste après une rotation de la clé partagée.
#
# PAS DE `set -e`, même doctrine que l'agent d'enrôlement : son métier est de
# survivre à ce qui tombe. Un watchdog qui meurt sur un code de retour est un
# kit sans bascule, en silence.
# =============================================================================
set -u

ICI="$(cd "$(dirname "$0")" && pwd)"
. "$ICI/roles/commun.sh"

WG_ROLE="${WG_ROLE:-kit}"
IFACE="${WATCHDOG_IFACE:-wg0}"
ENDPOINTS="$CONTROLE/endpoints.txt"
PORT="$CONTROLE/port"

# Les valeurs du corpus. Surchargeables : la recette ne va pas attendre 30 s
# par cas — et le critère de fini (« bascule ≤ 60 s ») se lit sur le défaut.
CIBLE="${WATCHDOG_CIBLE:-10.100.0.1}"
PERIODE="${WATCHDOG_PERIODE_S:-30}"
TOURS_MAX="${WATCHDOG_TOURS:-0}"        # 0 = sans fin, le régime du kit

journal() { printf 'wg(watchdog): %s\n' "$*" >&2; }

# L'endpoint suivant dans la liste, en ROTATION CIRCULAIRE à partir de celui
# que porte l'interface. Deux cas particuliers, tous deux voulus :
#   - endpoint courant introuvable dans la liste (la liste vient d'être
#     réécrite par l'agent d'enrôlement) → on repart de la tête ;
#   - liste d'un seul endpoint → on repose le même. `wg set` est idempotent,
#     et le kit n'a de toute façon nulle part où aller : mieux vaut réarmer
#     le peer que ne rien faire du tout.
suivant() { # $1 IP courante (peut être vide)
  awk -v courante="$1" '
    /^[0-9]/ { n++; ip[n] = $1; if ($1 == courante) index_courant = n }
    END {
      if (n == 0) exit 1
      if (index_courant == "" || index_courant == n) print ip[1]
      else print ip[index_courant + 1]
    }' "$ENDPOINTS" 2>/dev/null
}

commuter() {
  # La clé du peer : lue sur l'INTERFACE. Un fichier de plus serait un
  # troisième point de vérité, et une variable d'environnement figerait la
  # clé d'avant la rotation (arbitrage Q7).
  _cle="$(wg show "$IFACE" peers 2>/dev/null | head -1)"
  if [ -z "$_cle" ]; then
    journal "aucun peer sur $IFACE — rien à commuter (le kit n'est pas encore enrôlé ?)"
    return 1
  fi
  _courant="$(wg show "$IFACE" endpoints 2>/dev/null | awk 'NR==1{print $2}')"
  _ip_courante="${_courant%:*}"

  _cible="$(suivant "$_ip_courante")"
  if [ -z "$_cible" ]; then
    journal "endpoints.txt vide ou absent — aucune bascule possible"
    return 1
  fi
  # RELU À CHAQUE COMMUTATION, jamais mémorisé (arbitrage N4).
  _port=51820
  lisible "$PORT" && _port="$(head -1 "$PORT")"
  case "$_port" in ''|*[!0-9]*) _port=51820 ;; esac

  if wg set "$IFACE" peer "$_cle" endpoint "$_cible:$_port"; then
    journal "bascule : $_ip_courante → $_cible:$_port"
    return 0
  fi
  journal "échec de la bascule vers $_cible:$_port — nouvel essai au prochain battement"
  return 1
}

journal "démarrage — cible=$CIBLE période=${PERIODE}s interface=$IFACE (annexe 2 §3.4)"
tour=0
while :; do
  tour=$((tour + 1))
  sleep "$PERIODE"

  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    # Au premier démarrage l'interface n'existe pas encore : il faut
    # d'abord que l'agent d'enrôlement obtienne une identité. Ce n'est pas
    # une panne, et il n'y a rien à faire basculer.
    journal "$IFACE absente — rien à surveiller pour l'instant"
  elif ping -c3 -W2 "$CIBLE" >/dev/null 2>&1; then
    : # le chemin COMPLET répond : rien à faire, et surtout rien à écrire
  else
    journal "$CIBLE muet — le chemin complet est rompu"
    commuter
  fi

  if [ "$TOURS_MAX" -ne 0 ] && [ "$tour" -ge "$TOURS_MAX" ]; then break; fi
done
journal "arrêt après $tour tour(s)"
