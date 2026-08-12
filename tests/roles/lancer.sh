#!/usr/bin/env bash
# =============================================================================
# Cas R-01 … R-06 — la maquette MINIMALE des trois rôles de l'image `wg`
# (critère de fini 1 du lot 2, plan §4 : « les trois rôles montent leurs
# interfaces en maquette minimale »).
#
# Ce que la maquette prouve, et rien de plus (les règles netfilter sont
# lot 4, l'agent d'enrôlement et le watchdog sont les tranches 2 et 3) :
#   - l'image est UNIQUE (annexe 7 §1) : un seul condensat, WG_ROLE aiguille ;
#   - serveur : wg0 monte, 10.100.0.1/24, écoute 51821, AUCUNE route posée
#     (feuille — arch. §4.2) ;
#   - passerelle : wg-kits (51820) et wg-core montent ; la paire wg-core naît
#     LOCALEMENT au premier démarrage (annexe 3 §2.4), sa publique est écrite ;
#   - kit : wg0 monte avec MTU 1360 et Table = off — AUCUNE route par défaut
#     dans le tunnel (piège 11), l'invariant qui protège tout le LAN.
#
# Chaque conteneur tourne dans SON netns (pas host) : la maquette n'a pas
# besoin du réseau de l'hôte pour prouver qu'un rôle monte son interface, et
# elle n'y touche pas. NET_ADMIN + le module wireguard de l'hôte suffisent.
#
# Requiert : docker, sudo (création d'interface wireguard), le module noyau
# wireguard chargé. Un prérequis manquant => cas SAUTÉ, jamais vert.
#
# Usage :  sudo ./tests/roles/lancer.sh
# =============================================================================
set -u
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMG="${IMG_WG:-consultom/wg:dev}"
BAC="$(mktemp -d)"
ECHECS=0 ; SAUTES=0 ; N=0
NOMS=""

nettoyer() {
  for n in $NOMS; do docker rm -f "$n" >/dev/null 2>&1; done
  rm -rf "$BAC"
}
trap nettoyer EXIT
ok()   { printf '  \033[32mok\033[0m %s\n' "$1"; }
ko()   { printf '  \033[31mnon ok\033[0m %s — %s\n' "$1" "${2:-}"; ECHECS=$((ECHECS+1)); }
saute(){ printf '  \033[33m~ sauté\033[0m %s — %s\n' "$1" "$2"; SAUTES=$((SAUTES+1)); }
cas()  { N=$((N+1)); printf '\n# %s\n' "$1"; }

# --- prérequis ---------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "1..0 # docker absent — maquette non exécutable"; exit 0; fi
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "1..0 # image $IMG absente (docker build docker/wg) — sautée"; exit 0; fi
if ! lsmod 2>/dev/null | grep -q '^wireguard'; then
  echo "1..0 # module noyau wireguard non chargé — sautée"; exit 0; fi
if [ "$(id -u)" -ne 0 ]; then
  echo "1..0 # sudo requis (création d'interface wireguard) — sautée"; exit 0; fi

# Un conteneur de rôle, dans son propre netns, NET_ADMIN.
lancer() { # $1 nom  $2 role  [args docker...]
  local nom="$1" role="$2"; shift 2
  NOMS="$NOMS $nom"
  docker run -d --name "$nom" --cap-add NET_ADMIN \
    -e "WG_ROLE=$role" "$@" "$IMG" >/dev/null 2>&1
}
dans() { docker exec "$1" sh -c "$2" 2>/dev/null; }
attendre_iface() { # $1 conteneur  $2 iface  -> 0 si montée sous ~15 s
  for _ in $(seq 1 15); do
    dans "$1" "ip link show $2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

genkey() { docker run --rm --entrypoint wg "$IMG" genkey; }
pubkey() { echo "$1" | docker run --rm -i --entrypoint wg "$IMG" pubkey; }

# =============================================================================
cas "R-01 — image UNIQUE : WG_ROLE aiguille, un rôle inconnu est refusé (annexe 7 §1)"
inconnu=$(docker run --rm -e WG_ROLE=zzz "$IMG" 2>&1 | head -1)
echo "$inconnu" | grep -q 'rôle inconnu' \
  && ok "un WG_ROLE inconnu est refusé au démarrage (aiguillage explicite)" \
  || ko "R-01" "rôle inconnu non refusé : $inconnu"
manquant=$(docker run --rm "$IMG" 2>&1 | head -1)
echo "$manquant" | grep -q 'WG_ROLE' \
  && ok "sans WG_ROLE, refus bruyant" || ko "R-01b" "$manquant"

# =============================================================================
cas "R-02 — rôle serveur : wg0 monte, 10.100.0.1/24, écoute 51821 (arch. §4.2)"
mkdir -p "$BAC/serveur"
sk=$(genkey)
cat > "$BAC/serveur/wg0.conf" <<CONF
[Interface]
Address = 10.100.0.1/24
ListenPort = 51821
PrivateKey = $sk
CONF
lancer wg-srv serveur -v "$BAC/serveur:/etc/wireguard"
if attendre_iface wg-srv wg0; then
  ok "wg0 montée"
  addr=$(dans wg-srv "ip -br addr show wg0")
  echo "$addr" | grep -q '10.100.0.1/24' && ok "adresse 10.100.0.1/24" || ko "R-02" "addr=$addr"
  port=$(dans wg-srv "wg show wg0 listen-port")
  [ "$port" = "51821" ] && ok "écoute sur 51821" || ko "R-02" "port=$port"
  rts=$(dans wg-srv "ip route show dev wg0 | grep -v '10.100.0.0/24' | wc -l")
  [ "$rts" = "0" ] && ok "aucune route ajoutée hors le lien (feuille — arch. §4.2)" \
    || ko "R-02" "routes inattendues sur wg0"
else
  ko "R-02" "wg0 jamais montée ($(docker logs wg-srv 2>&1 | tail -1))"
fi

# =============================================================================
cas "R-03 — rôle passerelle : wg-kits (51820) et wg-core montent (annexe 3 §3.2)"
mkdir -p "$BAC/passerelle"
# VAULT LIVRE UNE CLÉ, PAS UNE CONFIGURATION (annexe 3 §2.4, arbitrage
# Q12). On dépose donc exactement ce que le provisionnement dépose — la
# clé, et rien d'autre — et c'est au rôle de rendre `wg-kits.conf`.
# Écrire la conf ici masquerait le trou : sur un nœud réel, personne ne
# l'écrirait, `wg-quick` n'aurait pas de fichier, et AUCUNE passerelle ne
# monterait jamais.
kits_sk=$(genkey)
printf '%s\n' "$kits_sk" > "$BAC/passerelle/wg-kits.key"
chmod 600 "$BAC/passerelle/wg-kits.key"
srv_sk=$(genkey); srv_pk=$(pubkey "$srv_sk")
lancer wg-gw passerelle -v "$BAC/passerelle:/etc/wireguard" \
  -e WG_CORE_ADRESSE=10.100.0.2/32 \
  -e SERVEUR_ENDPOINT=203.0.113.1:51821 \
  -e SERVEUR_CLE_PUBLIQUE="$srv_pk"
if attendre_iface wg-gw wg-kits && attendre_iface wg-gw wg-core; then
  ok "wg-kits et wg-core montées"
  kp=$(dans wg-gw "wg show wg-kits listen-port")
  [ "$kp" = "51820" ] && ok "wg-kits écoute 51820" || ko "R-03" "port kits=$kp"
  dans wg-gw "test -f /etc/wireguard/wg-kits.conf" \
    && ok "wg-kits.conf RENDU depuis la seule clé tirée de Vault (arbitrage Q12)" \
    || ko "R-03" "wg-kits.conf jamais rendue — personne ne l'écrit, aucune passerelle ne monte"
  # `Table = off` va avec `Address = 10.200.0.0/16` : sans lui, wg-quick
  # poserait une route /16 vers wg-kits, alors que les /32 des kits
  # arrivent avec leurs peers (piège 11).
  dans wg-gw "grep -q '^Table *= *off' /etc/wireguard/wg-kits.conf" \
    && ok "et elle porte Table = off (piège 11)" \
    || ko "R-03" "wg-kits.conf sans Table = off"
  dans wg-gw "test -f /etc/wireguard/wg-core.pub" \
    && ok "paire wg-core née localement, publique écrite (annexe 3 §2.4/§6.1)" \
    || ko "R-03" "wg-core.pub absente"
  peers=$(dans wg-gw "wg show wg-core peers | wc -l")
  [ "$peers" = "1" ] && ok "wg-core : un seul peer (le serveur)" || ko "R-03" "peers=$peers"
else
  ko "R-03" "interfaces jamais montées ($(docker logs wg-gw 2>&1 | tail -1))"
fi

# =============================================================================
cas "R-04 — rôle passerelle : la clé wg-core NE quitte pas le nœud (600, umask 077)"
if docker ps -a --format '{{.Names}}' | grep -q '^wg-gw$'; then
  perm=$(dans wg-gw "stat -c '%a' /etc/wireguard/wg-core.key")
  [ "$perm" = "600" ] && ok "wg-core.key en 600 (seule la publique est déclarée, §6.1)" \
    || ko "R-04" "perm=$perm"
else
  saute "R-04" "R-03 n'a pas démarré la passerelle"
fi

# =============================================================================
cas "R-05 — rôle kit : wg0 monte une conf Table=off, MTU 1360, sans route par défaut (piège 11)"
mkdir -p "$BAC/kit"
kit_sk=$(genkey); gw_sk=$(genkey); gw_pk=$(pubkey "$gw_sk")
cat > "$BAC/kit/wg0.conf" <<CONF
[Interface]
Address = 10.200.1.2/32
PrivateKey = $kit_sk
MTU = 1360
Table = off

[Peer]
PublicKey = $gw_pk
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
CONF
lancer wg-kit kit -v "$BAC/kit:/etc/wireguard"
if attendre_iface wg-kit wg0; then
  ok "wg0 montée"
  mtu=$(dans wg-kit "cat /sys/class/net/wg0/mtu")
  [ "$mtu" = "1360" ] && ok "MTU 1360 (4G + double encapsulation — piège 3)" || ko "R-05" "mtu=$mtu"
  rk=$(dans wg-kit "ip route show table all dev wg0 | grep -c 'default'")
  [ "$rk" = "0" ] && ok "aucune route par défaut posée par le tunnel (Table = off — piège 11)" \
    || ko "R-05" "le tunnel a posé une route par défaut — Table=off non respecté"
else
  ko "R-05" "wg0 jamais montée ($(docker logs wg-kit 2>&1 | tail -1))"
fi

# =============================================================================
cas "R-06 — le rôle kit n'invoque JAMAIS netfilter (arbitrage Q1, annexe 2 §3.1)"
kitcode="$RACINE/docker/wg/roles/kit.sh $RACINE/docker/wg/roles/commun.sh"
if grep -nE '\b(iptables|ip6tables|ipset|nft)\b' $kitcode >/dev/null 2>&1; then
  ko "R-06" "appel netfilter dans le chemin du rôle kit : $(grep -nE '\b(iptables|ipset|nft)\b' $kitcode | head -1)"
else
  ok "aucun appel iptables/ipset/nft dans kit.sh ni commun.sh"
fi

# =============================================================================
echo
echo "1..$((N))"
printf '# Bilan : %d cas, %d échec(s), %d sauté(s)\n' "$N" "$ECHECS" "$SAUTES"
[ "$ECHECS" -eq 0 ]
