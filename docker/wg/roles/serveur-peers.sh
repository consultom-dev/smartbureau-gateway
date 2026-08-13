# shellcheck shell=sh
# Pas de shebang : sourcé par serveur.sh, jamais exécuté.
# =============================================================================
# L'applicateur du peer wg-core (arbitrage Q20) — le « geste » que Q17
# renvoyait à l'image du rôle serveur de `wg`.
#
# wg-core-ctl (bridgé, sans privilège) écrit l'ÉTAT DÉSIRÉ des peers de
# passerelle dans un fichier ; ce code — en netns hôte, dans `wg-core`, seul
# à voir `wg0` — le RÉCONCILIE sur l'interface. La frontière est un fichier
# (motif parefeu-console/parefeu), jamais un privilège partagé.
#
# Idempotence, comme l'agent de passerelle (annexe 3 §4.1) : le diff porte
# sur l'état RÉEL (`wg show`), jamais sur une liste mémorisée — un
# redémarrage de `wg-core`, une pose manuelle convergent sans intervention.
#
# Le piège des peers statiques (annexe 1 §6.4) : `wg0` porte AUSSI la VM
# d'usine (10.100.0.100), provisionnée dans `wg0.conf`. On lit cet ensemble
# statique depuis le conf monté (source de vérité) et on ne réconcilie que
# le DELTA dynamique — un peer statique n'est jamais retiré.
#
# ESPACE DE NOMS — POSIX sh n'a pas de `local` : ce fichier réserve les
# variables préfixées `_rp_` (reconcilier_peers), `_cle _ip` (boucle de
# lecture) et `_sp` (_peers_statiques).
# =============================================================================

WG_CORE_PEERS="${WG_CORE_PEERS:-/etc/wg-core-peers/peers.json}"
WG_CORE_INTERVALLE="${WG_CORE_INTERVALLE:-10}"

# Défense en profondeur : rien de non vérifié ne descend vers `wg set`, même
# si wg-core-ctl a déjà validé (la leçon de l'injection dans /metrics).
_cle_ok() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9+/]{43}=$'; }
# Dernier octet 0-255 (pas 0-999) : le filet reste correct, même derrière le
# validateur strict de wg-core-ctl (suggestion de relecture Q20).
_ip_ok()  { printf '%s' "$1" | grep -Eq '^10\.100\.0\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/32$'; }

# Les clés publiques des [Peer] STATIQUES, lues du conf provisionné (source
# de vérité). Tolère `PublicKey = X` comme `PublicKey=X`.
_peers_statiques() { # $1 interface
  [ -f "$WG_CONF/$1.conf" ] || return 0
  grep -iE '^[[:space:]]*PublicKey[[:space:]]*=' "$WG_CONF/$1.conf" 2>/dev/null \
    | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//'
}

# UNE passe de réconciliation. Testable seule (le banc l'appelle directement).
reconcilier_peers() { # $1 interface (wg0)
  _rp_if="$1"
  # État désiré pas encore écrit → on ATTEND : un fichier absent n'est pas un
  # « ensemble vide » (qui, lui, retirerait tout). wg-core-ctl pas encore
  # démarré ne doit jamais faire tomber les peers en place.
  [ -e "$WG_CORE_PEERS" ] || return 0
  # Couplage lâche : si l'interface n'est pas là, on réessaiera (annexe 3 §4.1).
  ip link show "$_rp_if" >/dev/null 2>&1 || return 0

  _rp_tmp="$(mktemp -d)" || return 0
  if ! jq -r '.peers[]? | "\(.cle_publique)\t\(.allowed_ips)"' \
        "$WG_CORE_PEERS" > "$_rp_tmp/desir" 2>/dev/null; then
    journal "peers.json illisible — passe ignorée, l'état en place est conservé"
    rm -rf "$_rp_tmp"; return 0
  fi
  _peers_statiques "$_rp_if" | sort -u > "$_rp_tmp/statiques"

  # Ajouts et mises à jour : `wg set … allowed-ips` est idempotent.
  : > "$_rp_tmp/desir_cles"
  while IFS='	' read -r _cle _ip; do
    [ -n "$_cle" ] || continue
    if ! _cle_ok "$_cle" || ! _ip_ok "$_ip"; then
      journal "entrée d'état désiré rejetée (clé ou allowed-ips invalide)"
      continue
    fi
    printf '%s\n' "$_cle" >> "$_rp_tmp/desir_cles"
    wg set "$_rp_if" peer "$_cle" allowed-ips "$_ip" \
      || journal "wg set (ajout) a échoué pour un peer — réessai au prochain tour"
  done < "$_rp_tmp/desir"

  # Retraits : présents sur wg0, mais ni désirés ni statiques. Le peer
  # statique (VM d'usine) est hors périmètre par construction.
  wg show "$_rp_if" peers 2>/dev/null | while read -r _cle; do
    [ -n "$_cle" ] || continue
    grep -Fxq "$_cle" "$_rp_tmp/desir_cles" 2>/dev/null && continue
    grep -Fxq "$_cle" "$_rp_tmp/statiques" 2>/dev/null && continue
    wg set "$_rp_if" peer "$_cle" remove \
      || journal "wg set (retrait) a échoué pour un peer — réessai au prochain tour"
  done

  rm -rf "$_rp_tmp"
}

reconcilier_en_boucle() { # $1 interface (wg0)
  while :; do
    reconcilier_peers "$1"
    sleep "$WG_CORE_INTERVALLE"
  done
}
