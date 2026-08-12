#!/bin/sh
# =============================================================================
# Les règles netfilter de la PASSERELLE (annexe 3 §3.2).
#
# Script à part, et pas une fonction du rôle : c'est LUI qu'exécute la
# recette d'invariants (`tests/netfilter/`, P-01 …), dans un netns où
# aucune interface WireGuard réelle n'existe. Même forme que le plancher
# `reseau-hote` du kit, pour la même raison — on teste ce qu'on déploie.
#
#   netfilter-passerelle.sh            pose les règles, une fois
#   netfilter-passerelle.sh --oter     les retire (le `trap` du rôle)
#   netfilter-passerelle.sh --boucle   pose et RÉAFFIRME toutes les 30 s
#
# CE QU'IL POSE, ET DANS QUEL ORDRE — l'ordre EST la politique :
#
#   1. DROP   wg-kits → wg-kits     le hub-and-spoke (invariant 2)
#   2. ACCEPT wg-kits → wg-core     le chemin autorisé
#   3. ACCEPT wg-core → wg-kits     les retours établis
#   4. ACCEPT wg-kits → publique    la sortie internet, PAR KIT (ipset)
#   5. ACCEPT publique → wg-kits    les retours établis
#   6. REJECT wg-kits               le fourre-tout, EN DERNIER
#   7. REJECT INPUT wg-kits         l'autre verrou (invariant 4)
#
# Posées en `-C` puis `-A` (arbitrage Q8) : en queue, dans l'ordre écrit.
# Une pose en `-I` inverserait la liste et mettrait le REJECT (6) devant
# l'ACCEPT (2) — la passerelle couperait toute la flotte qu'elle sert, dès
# le premier démarrage, sans qu'une seule règle soit fausse isolément.
#
# LE SILENCE ET LE REFUS NE DISENT PAS LA MÊME CHOSE (arbitrage Q9) : (1)
# est un DROP — un kit n'a pas à apprendre que ses voisins existent — et
# (6) un REJECT `icmp-admin-prohibited`, parce qu'un kit hors de l'ipset
# n'est pas en panne, il est NON AUTORISÉ. Sans `--reject-with` explicite,
# les deux produiraient le même silence (RFC 1122 §4.2.3.9).
#
# CE QU'IL NE FAIT PAS : il ne monte aucune interface (c'est le rôle), ne
# peuple pas l'ipset (c'est l'agent de passerelle, §4.1 — ici on ne fait
# que la CRÉER, vide : une ipset absente ferait échouer la règle 4, et le
# fail-closed deviendrait un fail-open silencieux au redémarrage).
# =============================================================================
set -u

IFACES_PUBLIQUES="${IFACES_PUBLIQUES:-eth0}"
IFACE_KITS="${IFACE_KITS:-wg-kits}"
IFACE_CORE="${IFACE_CORE:-wg-core}"
RESEAU_KITS="${RESEAU_KITS:-10.200.0.0/16}"
IPSET_INTERNET="${IPSET_INTERNET:-internet_ok}"
PERIODE="${NETFILTER_PERIODE_S:-30}"
TOURS_MAX="${NETFILTER_TOURS:-0}"       # 0 = sans fin, le régime du nœud
case "$PERIODE"   in ''|*[!0-9]*) PERIODE=30 ;; esac
case "$TOURS_MAX" in ''|*[!0-9]*) TOURS_MAX=0 ;; esac

# `-w` PARTOUT : le verrou xtables est partagé avec dockerd, qui repose ses
# propres règles à chaque conteneur qui démarre. Sans lui, une pose échoue
# au hasard, et la règle manquante ne se voit qu'à la panne.
IPT="iptables -w 5"

journal() { printf 'wg(netfilter-passerelle): %s\n' "$*" >&2; }

# Piège 9 de l'architecture : en backend legacy, les règles seraient posées
# dans une table que PERSONNE ne lit — muettes, et tous les tests
# faussement verts. Formulation fail-safe : on exige la PRÉSENCE de
# « nf_tables », on ne refuse pas seulement « legacy ».
iptables --version 2>/dev/null | grep -q nf_tables || {
  journal "backend netfilter « $(iptables --version 2>&1) » — nf_tables exigé (piège 9)"
  exit 1
}

# `-C` puis `-A` : vérifier avant d'agir, et poser EN QUEUE (arbitrage Q8).
regle() { # $1 table  $2 chaîne  $* spec
  _table="$1"; _chaine="$2"; shift 2
  $IPT -t "$_table" -C "$_chaine" "$@" 2>/dev/null && return 0
  $IPT -t "$_table" -A "$_chaine" "$@"
}

oter() { # mêmes arguments — le retrait est idempotent lui aussi
  _table="$1"; _chaine="$2"; shift 2
  $IPT -t "$_table" -C "$_chaine" "$@" 2>/dev/null || return 0
  $IPT -t "$_table" -D "$_chaine" "$@"
}

poser() {
  # L'ipset AVANT la règle qui la référence : `-m set --match-set` échoue
  # si l'ensemble n'existe pas, et la règle 4 manquerait en silence.
  # `-exist` la rend idempotente ET conserve son contenu — la vider au
  # redémarrage couperait l'internet de toute la flotte servie le temps que
  # l'agent de passerelle repasse (invariant 1 : elle plafonne, on ne la
  # vide pas « pour dépanner »).
  ipset create "$IPSET_INTERNET" hash:ip -exist || {
    journal "ipset $IPSET_INTERNET impossible à créer — la sortie internet ne serait pas filtrée"
    return 1
  }

  # 1. Le hub-and-spoke. Les AllowedIPs filtrent la SOURCE, pas la
  #    destination : sans cette règle, la passerelle relaierait un kit vers
  #    un autre (invariant 2).
  regle filter FORWARD -i "$IFACE_KITS" -o "$IFACE_KITS" -j DROP || return 1

  # 2 et 3. Le chemin autorisé, et lui seul.
  regle filter FORWARD -i "$IFACE_KITS" -o "$IFACE_CORE" -j ACCEPT || return 1
  regle filter FORWARD -i "$IFACE_CORE" -o "$IFACE_KITS" \
        -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || return 1
  # Le masquerade rend la bascule invisible du serveur : quelle que soit la
  # passerelle empruntée, il voit une source unique.
  regle nat POSTROUTING -o "$IFACE_CORE" -j MASQUERADE || return 1

  # 4 et 5. La sortie internet centralisée, PAR KIT.
  for _pub in $IFACES_PUBLIQUES; do
    regle filter FORWARD -i "$IFACE_KITS" -o "$_pub" \
          -m set --match-set "$IPSET_INTERNET" src -j ACCEPT || return 1
    regle filter FORWARD -i "$_pub" -o "$IFACE_KITS" \
          -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || return 1
    regle nat POSTROUTING -s "$RESEAU_KITS" -o "$_pub" -j MASQUERADE || return 1
  done

  # 6. Le fourre-tout, EN DERNIER, et EXPLICITE (arbitrage Q9).
  regle filter FORWARD -i "$IFACE_KITS" -j REJECT \
        --reject-with icmp-admin-prohibited || return 1
  # 7. L'AUTRE verrou : le REJECT de FORWARD ne protège pas les services de
  #    la passerelle elle-même — un paquet adressé à une IP locale passe par
  #    INPUT (invariant 4). N'en poser qu'un laisse l'autre chemin ouvert,
  #    et le pare-feu public ne le rattrape pas : il raisonne sur
  #    l'interface publique, pas sur wg-kits.
  regle filter INPUT -i "$IFACE_KITS" -j REJECT || return 1
  return 0
}

retirer_tout() {
  oter filter INPUT -i "$IFACE_KITS" -j REJECT
  oter filter FORWARD -i "$IFACE_KITS" -j REJECT --reject-with icmp-admin-prohibited
  for _pub in $IFACES_PUBLIQUES; do
    oter nat POSTROUTING -s "$RESEAU_KITS" -o "$_pub" -j MASQUERADE
    oter filter FORWARD -i "$_pub" -o "$IFACE_KITS" \
         -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    oter filter FORWARD -i "$IFACE_KITS" -o "$_pub" \
         -m set --match-set "$IPSET_INTERNET" src -j ACCEPT
  done
  oter nat POSTROUTING -o "$IFACE_CORE" -j MASQUERADE
  oter filter FORWARD -i "$IFACE_CORE" -o "$IFACE_KITS" \
       -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  oter filter FORWARD -i "$IFACE_KITS" -o "$IFACE_CORE" -j ACCEPT
  oter filter FORWARD -i "$IFACE_KITS" -o "$IFACE_KITS" -j DROP
  # L'ipset SURVIT au retrait : elle porte l'autorisation de toute la
  # flotte servie, et l'agent de passerelle est seul à la peupler. La
  # détruire ici ferait payer un `compose restart` à 10 000 kits.
  journal "règles retirées (l'ipset $IPSET_INTERNET est conservée)"
}

case "${1:-}" in
  --oter)
    retirer_tout ;;
  --boucle)
    # RÉAFFIRMATION : docker et les redémarrages repoussent les règles.
    # C'est une boucle, pas un `depends_on` : elle rattrape aussi une
    # interface publique apparue tardivement.
    trap 'retirer_tout; exit 0' TERM INT
    tour=0
    while :; do
      tour=$((tour + 1))
      poser || journal "pose incomplète — nouvel essai au prochain cycle"
      if [ "$TOURS_MAX" -ne 0 ] && [ "$tour" -ge "$TOURS_MAX" ]; then break; fi
      sleep "$PERIODE"
    done ;;
  "")
    poser || exit 1
    journal "règles posées (annexe 3 §3.2 — sortie publique : $IFACES_PUBLIQUES)" ;;
  *)
    journal "argument inconnu « $1 » — attendu : --oter, --boucle, ou rien"
    exit 2 ;;
esac
