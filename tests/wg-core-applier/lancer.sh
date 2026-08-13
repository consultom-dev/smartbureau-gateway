#!/usr/bin/env bash
# =============================================================================
# Cas APP-01 … APP-06 — l'applicateur du peer wg-core (arbitrage Q20), le
# « geste » du rôle serveur : réconcilier l'état désiré (écrit par
# wg-core-ctl) sur un VRAI wg0.
#
# On fait tourner le RÔLE SERVEUR complet (image `wg`, WG_ROLE=serveur) dans
# son propre netns, avec un wg0.conf provisionné qui porte un peer STATIQUE
# (la VM d'usine). On pilote l'applicateur par le seul canal réel : on écrit
# peers.json sur le volume partagé, et on observe wg0 converger.
#
# Ce que ces cas prouvent :
#   - état désiré ABSENT ≠ vide : rien n'est retiré (le statique reste) ;
#   - ajouts et retraits appliqués sur wg0 (wg set) ;
#   - le peer STATIQUE n'est JAMAIS touché, même sur un état désiré VIDE ;
#   - convergence après REDÉMARRAGE de wg-core (peers dynamiques re-posés) ;
#   - défense en profondeur : une entrée invalide est ignorée, pas posée.
#
# Requiert : docker, sudo (interface wireguard), module noyau wireguard,
# image consultom/wg:dev. Un prérequis manquant => cas SAUTÉ, jamais vert.
#
# Usage :  sudo ./tests/wg-core-applier/lancer.sh
# =============================================================================
set -u
IMG="${IMG_WG:-consultom/wg:dev}"
BAC="$(mktemp -d)"
CONTENEUR="wg-applier-$$"
ECHECS=0 ; SAUTES=0 ; N=0

nettoyer() {
  docker rm -f "$CONTENEUR" >/dev/null 2>&1
  rm -rf "$BAC"
}
trap nettoyer EXIT
ok()   { printf '  \033[32mok\033[0m %s\n' "$1"; }
ko()   { printf '  \033[31mnon ok\033[0m %s — %s\n' "$1" "${2:-}"; ECHECS=$((ECHECS+1)); }
saute(){ printf '  \033[33m~ sauté\033[0m %s — %s\n' "$1" "$2"; SAUTES=$((SAUTES+1)); }
cas()  { N=$((N+1)); printf '\n# %s\n' "$1"; }

# --- prérequis ---------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "1..0 # docker absent — non exécutable"; exit 0; fi
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "1..0 # image $IMG absente (docker build docker/wg) — sautée"; exit 0; fi
if ! lsmod 2>/dev/null | grep -q '^wireguard'; then
  echo "1..0 # module noyau wireguard non chargé — sautée"; exit 0; fi
if [ "$(id -u)" -ne 0 ]; then
  echo "1..0 # sudo requis (création d'interface wireguard) — sautée"; exit 0; fi

genkey() { docker run --rm --entrypoint wg "$IMG" genkey; }
pubkey() { echo "$1" | docker run --rm -i --entrypoint wg "$IMG" pubkey; }
dans()   { docker exec "$CONTENEUR" sh -c "$1" 2>/dev/null; }

# Le peer STATIQUE (VM d'usine) et deux passerelles dynamiques.
STATIQUE_PK=$(pubkey "$(genkey)")
GW1_PK=$(pubkey "$(genkey)")
GW2_PK=$(pubkey "$(genkey)")

# wg0.conf PROVISIONNÉ : [Interface] + le seul peer statique.
mkdir -p "$BAC/wg" "$BAC/peers"
SRV_SK=$(genkey)
cat > "$BAC/wg/wg0.conf" <<CONF
[Interface]
Address = 10.100.0.1/24
ListenPort = 51821
PrivateKey = $SRV_SK

[Peer]
# VM d'usine — statique, provisionnée, JAMAIS gérée par l'applicateur
PublicKey = $STATIQUE_PK
AllowedIPs = 10.100.0.100/32
CONF

# Écrit peers.json ATOMIQUEMENT sur le volume partagé (comme wg-core-ctl).
poser_peers() { # $1 = contenu JSON
  printf '%s\n' "$1" > "$BAC/peers/.tmp"
  mv -f "$BAC/peers/.tmp" "$BAC/peers/peers.json"
}
sans_peers() { rm -f "$BAC/peers/peers.json"; }

peer_present() { dans "wg show wg0 peers" | grep -Fxq "$1"; }

# Les conditions attendues, en prédicats nommés (0 = atteinte).
gw1_posee()        { peer_present "$GW1_PK"; }
deux_posees()      { peer_present "$GW1_PK" && peer_present "$GW2_PK"; }
gw2_retiree()      { ! peer_present "$GW2_PK"; }
dynamiques_vides() { ! peer_present "$GW1_PK" && ! peer_present "$GW2_PK"; }

# Attend une CONDITION (converge), plutôt qu'un délai fixe : l'applicateur
# scrute toutes les WG_CORE_INTERVALLE=1 s ; on lui laisse converger.
converge() { # $1 = nom d'un prédicat (fonction : 0 si la condition est atteinte)
  for _ in $(seq 1 15); do
    "$1" && return 0
    sleep 1
  done
  return 1
}

attendre_iface() {
  for _ in $(seq 1 15); do
    dans "ip link show wg0" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# --- Démarrage du rôle serveur, sans état désiré au départ -------------------
sans_peers
docker run -d --name "$CONTENEUR" --cap-add NET_ADMIN \
  -e WG_ROLE=serveur -e WG_CORE_INTERVALLE=1 \
  -v "$BAC/wg:/etc/wireguard" \
  -v "$BAC/peers:/etc/wg-core-peers" \
  "$IMG" >/dev/null 2>&1

if ! attendre_iface; then
  echo "1..0 # wg0 jamais montée ($(docker logs "$CONTENEUR" 2>&1 | tail -1)) — sautée"
  exit 0
fi

# =============================================================================
cas "APP-01 — état désiré ABSENT : rien n'est retiré, le statique reste (Q20)"
# Laisse quelques tours passer : un fichier absent ne doit JAMAIS être lu
# comme « ensemble vide » qui viderait wg0.
sleep 3
if peer_present "$STATIQUE_PK"; then
  ok "le peer statique (VM d'usine) est présent, sans état désiré"
else
  ko "APP-01" "le statique a disparu alors qu'aucun état désiré n'existe"
fi
nb=$(dans "wg show wg0 peers" | grep -c . )
[ "$nb" = "1" ] && ok "un seul peer sur wg0 (le statique) — aucun dynamique inventé" \
  || ko "APP-01" "nombre de peers inattendu : $nb"

# =============================================================================
cas "APP-02 — ajout : deux passerelles posées sur wg0 (wg set allowed-ips)"
poser_peers '{"peers":[
  {"gw_id":"gw-01","cle_publique":"'"$GW1_PK"'","allowed_ips":"10.100.0.2/32"},
  {"gw_id":"gw-02","cle_publique":"'"$GW2_PK"'","allowed_ips":"10.100.0.3/32"}]}'
if converge deux_posees; then
  ok "les deux passerelles sont posées sur wg0"
  aip=$(dans "wg show wg0 allowed-ips" | grep -F "$GW1_PK" | awk '{print $2}')
  [ "$aip" = "10.100.0.2/32" ] && ok "allowed-ips appliqué (10.100.0.2/32)" \
    || ko "APP-02" "allowed-ips=$aip"
  peer_present "$STATIQUE_PK" && ok "le statique est toujours là" \
    || ko "APP-02" "le statique a été perdu à l'ajout"
else
  ko "APP-02" "convergence des ajouts non atteinte ($(dans 'wg show wg0 peers'))"
fi

# =============================================================================
cas "APP-03 — retrait : une passerelle ôtée du fichier disparaît de wg0"
poser_peers '{"peers":[
  {"gw_id":"gw-01","cle_publique":"'"$GW1_PK"'","allowed_ips":"10.100.0.2/32"}]}'
if converge gw2_retiree; then
  ok "gw-02, ôtée de l'état désiré, est retirée de wg0"
  peer_present "$GW1_PK" && ok "gw-01, toujours désirée, reste posée" \
    || ko "APP-03" "gw-01 retirée à tort"
  peer_present "$STATIQUE_PK" && ok "le statique reste intact" \
    || ko "APP-03" "le statique perdu au retrait"
else
  ko "APP-03" "gw-02 toujours présente ($(dans 'wg show wg0 peers'))"
fi

# =============================================================================
cas "APP-04 — état désiré VIDE : tous les dynamiques partent, le statique NON"
poser_peers '{"peers":[]}'
if converge dynamiques_vides; then
  ok "aucun peer dynamique ne subsiste"
  peer_present "$STATIQUE_PK" \
    && ok "le peer STATIQUE survit à un état désiré vide (hors périmètre — Q20)" \
    || ko "APP-04" "le statique a été retiré par un état désiré vide — RÉGRESSION"
else
  ko "APP-04" "des dynamiques subsistent ($(dans 'wg show wg0 peers'))"
fi

# =============================================================================
cas "APP-05 — redémarrage de wg-core : les peers dynamiques sont re-posés (Q20)"
poser_peers '{"peers":[
  {"gw_id":"gw-01","cle_publique":"'"$GW1_PK"'","allowed_ips":"10.100.0.2/32"}]}'
converge gw1_posee >/dev/null
docker restart "$CONTENEUR" >/dev/null 2>&1
attendre_iface || ko "APP-05" "wg0 non remontée après redémarrage"
# Fraîche interface : les peers runtime sont perdus, le statique revient du
# conf, l'applicateur re-pose les dynamiques depuis peers.json (qui persiste).
if converge gw1_posee; then
  ok "gw-01 est re-posée après le redémarrage — sans intervention"
  peer_present "$STATIQUE_PK" && ok "le statique est revenu du conf provisionné" \
    || ko "APP-05" "le statique manquant après redémarrage"
else
  ko "APP-05" "gw-01 non re-posée ($(dans 'wg show wg0 peers'))"
fi

# =============================================================================
cas "APP-06 — défense en profondeur : une entrée invalide est ignorée, pas posée"
# wg-core-ctl valide en amont ; l'applicateur re-valide (leçon /metrics). Une
# clé publique invalide ne doit JAMAIS atteindre `wg set`.
poser_peers '{"peers":[
  {"gw_id":"gw-01","cle_publique":"'"$GW1_PK"'","allowed_ips":"10.100.0.2/32"},
  {"gw_id":"gw-mal","cle_publique":"pas-une-cle","allowed_ips":"10.100.0.4/32"},
  {"gw_id":"gw-mal2","cle_publique":"'"$GW2_PK"'","allowed_ips":"8.8.8.8/32"}]}'
converge gw1_posee >/dev/null
sleep 2   # laisse un tour de plus, au cas où les invalides seraient posées
nb=$(dans "wg show wg0 peers" | grep -c . )
# Attendu : statique + gw-01 = 2. Les deux entrées invalides écartées.
if [ "$nb" = "2" ] && peer_present "$GW1_PK" && ! peer_present "$GW2_PK"; then
  ok "l'entrée à clé invalide et celle hors-plan sont ignorées — 2 peers (statique + gw-01)"
else
  ko "APP-06" "une entrée invalide a été posée : $nb peer(s) — $(dans 'wg show wg0 peers')"
fi

# =============================================================================
printf '\n1..%d\n#\n' "$N"
REUSSIS=$((N - ECHECS - SAUTES))
printf '# Bilan : %d réussi(s), %d échoué(s), %d sauté(s)\n' "$REUSSIS" "$ECHECS" "$SAUTES"
[ "$ECHECS" -eq 0 ]
