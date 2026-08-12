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
# Posées en `-A`, dans l'ordre écrit (arbitrage Q8). Une pose en `-I`
# inverserait la liste et mettrait le REJECT (6) devant l'ACCEPT (2) — la
# passerelle couperait toute la flotte qu'elle sert, dès le premier
# démarrage, sans qu'une seule règle soit fausse isolément.
#
# L'ORDRE EST AUSSI CE QUE LA RÉAFFIRMATION DOIT RENDRE. Une règle
# manquante n'est donc PAS remise seule : la séquence entière est
# reconstruite. Remettre en queue l'ACCEPT (2) qu'un exploitant vient
# d'effacer la placerait DERRIÈRE le REJECT (6) — présente, comptée,
# vérifiable… et morte : toute la flotte perdrait wg-core, et la sonde
# resterait verte. Reconstruire coûte quelques appels iptables toutes les
# 30 s dans le seul cas où quelque chose a bougé ; c'est le prix de
# l'invariant.
#
# LA FENÊTRE DE RECONSTRUCTION EST FERMÉE, PAS OUVERTE : un DROP de
# barrage est posé en tête AVANT de démonter, et retiré après. Si le
# script meurt au milieu, les kits sont coupés — jamais relayés en clair
# entre eux.
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

# L'ipset est-elle utilisable ? Répondu une fois par tour, avant de bâtir
# la séquence : les règles 4 qui la référencent en dépendent.
IPSET_UTILISABLE=non

# --- LA SÉQUENCE, ÉCRITE UNE FOIS -------------------------------------------
# Une ligne par règle, « table chaîne spécification… », DANS L'ORDRE de
# l'annexe 3 §3.2. Pose, retrait et vérification lisent cette liste et elle
# seule : trois listes divergentes, c'est une règle qui se pose et ne se
# retire pas, ou qui se vérifie ailleurs qu'où elle est posée.
regles() {
  # 1. Le hub-and-spoke. Les AllowedIPs filtrent la SOURCE, pas la
  #    destination : sans cette règle, la passerelle relaierait un kit vers
  #    un autre (invariant 2).
  printf '%s\n' "filter FORWARD -i $IFACE_KITS -o $IFACE_KITS -j DROP"

  # 2 et 3. Le chemin autorisé, et lui seul.
  printf '%s\n' "filter FORWARD -i $IFACE_KITS -o $IFACE_CORE -j ACCEPT"
  printf '%s\n' "filter FORWARD -i $IFACE_CORE -o $IFACE_KITS -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"

  # 4 et 5. La sortie internet centralisée, PAR KIT.
  for _pub in $IFACES_PUBLIQUES; do
    # Sans ipset utilisable, cette règle est OMISE — pas posée sans son
    # `-m set`. Un kit non autorisé sortirait sinon comme les autres :
    # l'absence d'ensemble doit fermer la sortie internet, pas l'ouvrir.
    [ "$IPSET_UTILISABLE" = oui ] && \
      printf '%s\n' "filter FORWARD -i $IFACE_KITS -o $_pub -m set --match-set $IPSET_INTERNET src -j ACCEPT"
    printf '%s\n' "filter FORWARD -i $_pub -o $IFACE_KITS -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
  done

  # 6. Le fourre-tout, EN DERNIER, et EXPLICITE (arbitrage Q9).
  printf '%s\n' "filter FORWARD -i $IFACE_KITS -j REJECT --reject-with icmp-admin-prohibited"

  # 7. L'AUTRE verrou : le REJECT de FORWARD ne protège pas les services de
  #    la passerelle elle-même — un paquet adressé à une IP locale passe par
  #    INPUT (invariant 4). N'en poser qu'un laisse l'autre chemin ouvert,
  #    et le pare-feu public ne le rattrape pas : il raisonne sur
  #    l'interface publique, pas sur wg-kits.
  printf '%s\n' "filter INPUT -i $IFACE_KITS -j REJECT"

  # Le masquerade rend la bascule invisible du serveur : quelle que soit la
  # passerelle empruntée, il voit une source unique. Chaîne à part, ordre
  # indifférent (les `-o` sont disjoints) — en queue de liste pour que la
  # reconstruction de FORWARD passe en premier.
  printf '%s\n' "nat POSTROUTING -o $IFACE_CORE -j MASQUERADE"
  for _pub in $IFACES_PUBLIQUES; do
    printf '%s\n' "nat POSTROUTING -s $RESEAU_KITS -o $_pub -j MASQUERADE"
  done
}

# `appliquer <action>` : déroule la séquence en passant chaque règle à
# `$IPT -t table <action> chaîne spec`. Rend 1 si UNE seule a échoué.
appliquer() {
  _action="$1"; _echecs=0
  while read -r _ligne; do
    [ -n "$_ligne" ] || continue
    # Découpage voulu : la spécification est une liste d'arguments.
    # shellcheck disable=SC2086
    set -- $_ligne
    _t="$1"; _c="$2"; shift 2
    $IPT -t "$_t" "$_action" "$_c" "$@" || _echecs=$((_echecs + 1))
  done <<FIN
$(regles)
FIN
  [ "$_echecs" -eq 0 ]
}

# Combien de règles de la séquence manquent. Zéro = rien à faire : ce que
# nous avons posé, nous l'avons posé DANS L'ORDRE, et personne d'autre ne
# touche à ces règles-là.
manquantes() {
  _n=0
  while read -r _ligne; do
    [ -n "$_ligne" ] || continue
    # shellcheck disable=SC2086
    set -- $_ligne
    _t="$1"; _c="$2"; shift 2
    $IPT -t "$_t" -C "$_c" "$@" 2>/dev/null || _n=$((_n + 1))
  done <<FIN
$(regles)
FIN
  printf '%s\n' "$_n"
}

# Compter ne suffit pas : une règle peut être PRÉSENTE et morte. Le
# fourre-tout doit être la DERNIÈRE règle de FORWARD qui parle de wg-kits
# en entrée — tout ce qui le suit est inatteignable. C'est la seule
# propriété d'ordre qu'un `-C` ne sait pas dire.
ordre_conforme() {
  _derniere="$($IPT -t filter -S FORWARD 2>/dev/null | grep -e "-i $IFACE_KITS " -e "-o $IFACE_KITS " | tail -n 1)"
  case "$_derniere" in
    *"-i $IFACE_KITS -j REJECT"*) return 0 ;;
    *) return 1 ;;
  esac
}

BARRAGE="-i $IFACE_KITS -j DROP"

barrage_poser() {
  # shellcheck disable=SC2086
  $IPT -t filter -C FORWARD $BARRAGE 2>/dev/null && return 0
  # shellcheck disable=SC2086
  $IPT -t filter -I FORWARD 1 $BARRAGE
}

barrage_oter() {
  # shellcheck disable=SC2086
  $IPT -t filter -C FORWARD $BARRAGE 2>/dev/null || return 0
  # shellcheck disable=SC2086
  $IPT -t filter -D FORWARD $BARRAGE
}

etat_ipset() {
  # `-exist` la rend idempotente ET conserve son contenu — la vider au
  # redémarrage couperait l'internet de toute la flotte servie le temps que
  # l'agent de passerelle repasse (invariant 1 : elle plafonne, on ne la
  # vide pas « pour dépanner »).
  if ipset create "$IPSET_INTERNET" hash:ip -exist 2>/dev/null; then
    IPSET_UTILISABLE=oui
  else
    IPSET_UTILISABLE=non
    # On CONTINUE : sans ipset, la sortie internet des kits reste fermée,
    # mais le hub-and-spoke et le fourre-tout, eux, se posent. Abandonner
    # ici laisserait la passerelle relayer kit → kit en clair — un
    # fail-open, sur une panne d'outillage.
    journal "ipset $IPSET_INTERNET indisponible — sortie internet FERMÉE, le reste est posé"
  fi
}

poser() {
  etat_ipset
  _manquantes="$(manquantes)"
  if [ "$_manquantes" -eq 0 ] && ordre_conforme; then
    return 0
  fi

  if [ "$_manquantes" -eq 0 ]; then
    journal "les sept règles sont là mais le fourre-tout n'est plus dernier — séquence reposée"
  else
    journal "$_manquantes règle(s) manquante(s) — la séquence entière est reposée, dans l'ordre"
  fi
  barrage_poser || {
    journal "barrage impossible à poser — reconstruction ABANDONNÉE (les règles en place restent)"
    return 1
  }
  appliquer -D >/dev/null 2>&1        # démontage : les absentes rendent 1, sans importance
  if appliquer -A; then
    barrage_oter
    return 0
  fi
  journal "reconstruction incomplète — le barrage RESTE : les kits sont coupés, pas relayés"
  return 1
}

retirer_tout() {
  appliquer -D >/dev/null 2>&1
  barrage_oter
  # L'ipset SURVIT au retrait : elle porte l'autorisation de toute la
  # flotte servie, et l'agent de passerelle est seul à la peupler. La
  # détruire ici ferait payer un `compose restart` à 10 000 kits.
  journal "règles retirées (l'ipset $IPSET_INTERNET est conservée)"
}

case "${1:-}" in
  --oter)
    # Le retrait doit voir la MÊME séquence que la pose, ipset comprise :
    # sinon la règle 4 posée hier resterait derrière nous.
    ipset list -n 2>/dev/null | grep -qx "$IPSET_INTERNET" && IPSET_UTILISABLE=oui
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
      # `sleep` en arrière-plan et `wait` : un `sleep` au premier plan
      # retarderait le `trap` de toute la période — 30 s pendant lesquelles
      # `compose down` attend, puis tue, et les règles restent posées.
      sleep "$PERIODE" &
      wait $! 2>/dev/null || true
    done ;;
  "")
    poser || exit 1
    journal "règles posées (annexe 3 §3.2 — sortie publique : $IFACES_PUBLIQUES)" ;;
  *)
    journal "argument inconnu « $1 » — attendu : --oter, --boucle, ou rien"
    exit 2 ;;
esac
