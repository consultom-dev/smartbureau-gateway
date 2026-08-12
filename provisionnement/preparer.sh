#!/usr/bin/env bash
# =============================================================================
# Provisionnement d'une VM en PASSERELLE (annexe 3 §2).
#
# Critère de fini du lot 4 : « une VM neuve devient passerelle
# opérationnelle par une procédure automatisable ». Ce script EST cette
# procédure — pas une documentation de ce qu'il faudrait taper.
#
# Il fait quatre choses, dans cet ordre, et s'arrête à la première qui
# échoue :
#   1. la vérification des prérequis — module WireGuard, backend nf_tables,
#      et l'EXISTENCE des interfaces de sortie publique ;
#   2. les sysctls (§2.1) — un routeur qui NAT des milliers de clients
#      sature conntrack avant le CPU, et le forwarding v6 se VERROUILLE
#      (doctrine v4 seul, arch. §9) ;
#   3. le pare-feu public (§2.2) — POSÉ, pas affiché (arbitrage Q13) ;
#   4. le `.env` du nœud, à partir de ce que l'app a rendu à la
#      déclaration (§6.1).
#
# CE SCRIPT POSE, IL NE RÉCITE PAS. Une procédure de sécurité qui rend 0
# sans avoir agi est pire que pas de procédure : elle produit une
# confiance. Rien ne rattrape le pare-feu public en aval — le conteneur
# `wireguard` ne pose que des règles `-i wg-kits`, et l'invariant 4 dit
# précisément que les deux pare-feu ne se couvrent pas l'un l'autre.
#
# Ce qu'il NE fait PAS : tirer les secrets de Vault. Le chemin froid
# (annexe 5, invariant 4) appartient à l'exploitant, et un script qui
# détient un jeton Vault est un script qu'on ne peut plus laisser tourner
# sans surveillance. Il DIT ce qu'il attend, et refuse de continuer sans.
# =============================================================================
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSCTL_CIBLE="${SYSCTL_CIBLE:-/etc/sysctl.d/60-smartbureau-passerelle.conf}"
UNITE_CIBLE="${UNITE_CIBLE:-/etc/systemd/system/smartbureau-parefeu-public.service}"
APPLIQUER="${APPLIQUER:-1}"        # 0 = montrer sans poser (recette)

IPT="iptables -w 5"
IPT6="ip6tables -w 5"

journal() { printf 'provisionnement: %s\n' "$*" >&2; }
echec()   { journal "ERREUR — $*"; exit 1; }

# --- 1. sysctls (§2.1) -------------------------------------------------------
# `nf_conntrack_max` et la taille de table de hachage vont ENSEMBLE : monter
# l'un sans l'autre allonge les chaînes au lieu d'augmenter la capacité.
sysctls() {
  cat <<'CONF'
# Généré par provisionnement/preparer.sh — annexe 3 §2.1. Ne pas éditer.
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.netfilter.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_buckets=262144
net.netfilter.nf_conntrack_tcp_timeout_established=7200
net.core.rmem_max=26214400
net.core.wmem_max=26214400
# v6 VERROUILLÉ : la doctrine est v4 seul (arch. §9). Un forwarding v6
# ouvert contournerait en silence toutes les règles de l'annexe 3, qui ne
# raisonnent qu'en v4.
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
CONF
}

poser_sysctls() {
  if [ "$APPLIQUER" = "0" ]; then
    journal "sysctls (non appliqués, APPLIQUER=0) :"; sysctls; return 0
  fi
  # `nf_conntrack` AVANT `sysctl -p` : les clés `net.netfilter.*` n'existent
  # pas tant que le module n'est pas chargé, et sur une VM neuve où dockerd
  # n'a encore posé aucune règle NAT il ne l'est pas. `sysctl -p` rendrait
  # alors non-zéro, le script sortirait, et le `.env` ne serait jamais
  # écrit — un provisionnement qui échoue sur l'ordre de chargement d'un
  # module.
  modprobe nf_conntrack 2>/dev/null || true
  sysctls > "$SYSCTL_CIBLE"
  sysctl -p "$SYSCTL_CIBLE" >/dev/null || echec "sysctl -p a échoué sur $SYSCTL_CIBLE"
  journal "sysctls posés dans $SYSCTL_CIBLE"
}

# --- 2. Pare-feu public (§2.2) ----------------------------------------------
# Ce que le nœud accepte DEPUIS L'INTERNET, et rien d'autre : 51820/udp (les
# kits), 443/tcp (le proxy d'enrôlement), 22/tcp (l'administration). Le
# port 80 n'est PAS ouvert — le certificat vient de Vault, aucun challenge
# ACME ne s'exécute ici (§5).
#
# Le DROP porte sur l'INTERFACE PUBLIQUE, pas sur la politique de la
# chaîne : `lo`, les tunnels et le bridge docker restent joignables
# localement, et dockerd garde ses propres chaînes. Poser `-P INPUT DROP`
# à la place couperait des chemins que ce script ne connaît pas.
parefeu_regles() {   # émet « spécification… », une par ligne, DANS L'ORDRE
  local pub="$1"
  printf '%s\n' "-i $pub -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
  printf '%s\n' "-i $pub -p udp --dport 51820 -j ACCEPT"
  printf '%s\n' "-i $pub -p tcp --dport 443 -j ACCEPT"
  printf '%s\n' "-i $pub -p tcp --dport 22 -j ACCEPT"
  printf '%s\n' "-i $pub -j DROP"
}

parefeu_public() {   # la forme LISIBLE, pour l'inspection et la recette
  local pub="${1:-eth0}"
  echo "# Pare-feu public — annexe 3 §2.2. Interface : $pub"
  parefeu_regles "$pub" | sed 's/^/-A INPUT /'
}

poser_parefeu() {
  local pub_liste="${1:-eth0}" pub ligne
  if [ "$APPLIQUER" = "0" ]; then
    journal "pare-feu public (non appliqué, APPLIQUER=0) :"
    for pub in $pub_liste; do parefeu_public "$pub"; done
    return 0
  fi

  for pub in $pub_liste; do
    # `-C` puis `-A` : idempotent, et en QUEUE — le DROP fourre-tout est
    # écrit en dernier, il doit être évalué en dernier. Même convention que
    # les règles du conteneur `wireguard` (arbitrage Q8).
    while read -r ligne; do
      [ -n "$ligne" ] || continue
      # shellcheck disable=SC2086
      $IPT -C INPUT $ligne 2>/dev/null && continue
      # shellcheck disable=SC2086
      $IPT -A INPUT $ligne || echec "pare-feu public : « $ligne » refusée sur $pub"
    done < <(parefeu_regles "$pub")

    # VÉRIFIER APRÈS AVOIR POSÉ. Le fourre-tout est la règle qui ferme ;
    # s'il manque, tout ce qui écoute sur l'hôte est joignable depuis
    # l'Internet, et le reste des règles ne sert à rien.
    # shellcheck disable=SC2086
    $IPT -C INPUT -i "$pub" -j DROP 2>/dev/null \
      || echec "pare-feu public : le DROP fourre-tout est absent sur $pub après la pose"
    journal "pare-feu public posé sur $pub (51820/udp, 443/tcp, 22/tcp ; tout le reste fermé)"
  done

  # v6 EN BLOC. La flotte est v4 seule : une politique v6 en ACCEPT est une
  # seconde porte que personne n'inspecte. `disable_ipv6` du §2.1 la ferme
  # déjà côté pile ; ceci la ferme côté filtre, pour le cas où un noyau ou
  # un hyperviseur la rallume.
  if command -v ip6tables >/dev/null 2>&1; then
    $IPT6 -P INPUT DROP   2>/dev/null || journal "ATTENTION : politique v6 INPUT non posée"
    $IPT6 -P FORWARD DROP 2>/dev/null || journal "ATTENTION : politique v6 FORWARD non posée"
  else
    journal "ATTENTION : ip6tables absent — le v6 n'est fermé que par les sysctls"
  fi

  persister_parefeu "$pub_liste"
}

# La persistance : une unité systemd qui REJOUE cette même fonction au
# démarrage. Pas d'`iptables-save` global — il embarquerait les chaînes de
# dockerd, et les restaurer au boot avant que dockerd n'existe produirait
# des règles orphelines pointant vers des chaînes absentes.
persister_parefeu() {
  local pub_liste="$1"
  command -v systemctl >/dev/null 2>&1 || {
    journal "ATTENTION : systemd absent — le pare-feu public NE SURVIVRA PAS au redémarrage."
    journal "            rejouer « $0 parefeu » au boot, par le moyen de cet hôte."
    return 0
  }
  cat > "$UNITE_CIBLE" <<UNITE
[Unit]
Description=Pare-feu public de la passerelle SmartBureau (annexe 3 §2.2)
After=network-pre.target
Before=docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=IFACES_PUBLIQUES=$pub_liste
ExecStart=$RACINE/provisionnement/preparer.sh parefeu

[Install]
WantedBy=multi-user.target
UNITE
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable smartbureau-parefeu-public.service >/dev/null 2>&1 \
    || journal "ATTENTION : unité écrite mais non activée — l'activer à la main"
  journal "pare-feu public persisté ($UNITE_CIBLE, rejoué au démarrage)"
}

# --- 3. Prérequis ------------------------------------------------------------
verifier_prerequis() {
  command -v docker >/dev/null 2>&1 || echec "docker absent"
  iptables --version 2>/dev/null | grep -q nf_tables \
    || echec "backend netfilter legacy — nf_tables exigé (arch. piège 9)"

  # Les interfaces de sortie publique DOIVENT exister. netfilter accepte un
  # nom d'interface inexistant sans broncher : les règles seraient posées,
  # comptées, vérifiables — et jamais atteintes. Sur une VM en `ens3`
  # provisionnée avec le défaut `eth0`, la sortie internet de toute la
  # flotte servie serait morte, en silence.
  local pub
  for pub in ${IFACES_PUBLIQUES:-eth0}; do
    ip link show "$pub" >/dev/null 2>&1 \
      || echec "interface de sortie publique « $pub » inexistante — poser IFACES_PUBLIQUES (§7, arbitrage Q10)"
  done

  if [ "$APPLIQUER" != "0" ]; then
    modprobe wireguard 2>/dev/null || true
    ip link add essai-wg type wireguard 2>/dev/null \
      || echec "module WireGuard indisponible dans le noyau de l'hôte (§2.1)"
    ip link del essai-wg
  fi
  journal "prérequis vérifiés : docker, nf_tables, module wireguard, interfaces ${IFACES_PUBLIQUES:-eth0}"
}

# --- 4. Le `.env` du nœud (§6.1) --------------------------------------------
# Les quatre valeurs que l'app REND à la déclaration : l'IP core allouée
# (l'app alloue — arbitrage D4), le secret d'agent remis une fois, le nom
# public à publier en DNS, et l'endpoint du serveur.
ecrire_env() {
  local cible="$RACINE/.env"
  [ -f "$cible" ] && { journal ".env déjà présent — conservé (le secret d'agent ne se réémet pas)"; return 0; }
  local v
  for v in GW_ID DOMAINE WG_CORE_ADRESSE SERVEUR_ENDPOINT SERVEUR_CLE_PUBLIQUE AGENT_SECRET; do
    [ -n "${!v:-}" ] || echec "$v non défini — il vient de la déclaration (§6.1) et de Vault (§2.4)"
  done

  # Les images : par CONDENSAT en production. Le `release.env` de la release
  # les fixe ; sans lui, ce script écrirait `:dev` sur un nœud de
  # production — un tag mobile, ce que le dépôt interdit. On refuse, à moins
  # que l'exploitant ne le demande explicitement (bancs, maquette).
  if [ -z "${IMG_WG:-}${IMG_WG_AGENT:-}${IMG_PROXY_ENROLEMENT:-}" ] \
     && [ "${AUTORISER_IMAGES_DEV:-0}" != "1" ]; then
    echec "IMG_WG / IMG_WG_AGENT / IMG_PROXY_ENROLEMENT non définis — sourcer le release.env de la release (pas de tag mobile), ou poser AUTORISER_IMAGES_DEV=1 pour une maquette"
  fi

  # ÉCRITURE LIGNE À LIGNE, jamais par `sed`. Un secret d'agent contenant
  # `&`, `|` ou `\` serait réécrit par le remplacement lui-même : le `.env`
  # porterait un secret FAUX, sans erreur, et le nœud prendrait des 401
  # indéfiniment sans qu'une seule règle soit fausse.
  ( umask 077
    {
      printf '# Écrit par provisionnement/preparer.sh (annexe 3 §2, §6.1).\n'
      printf '# Il porte le secret d'"'"'agent : il ne se versionne JAMAIS.\n\n'
      printf 'GW_ID=%s\n'                "$GW_ID"
      printf 'DOMAINE=%s\n'              "$DOMAINE"
      printf 'IFACES_PUBLIQUES=%s\n'     "${IFACES_PUBLIQUES:-eth0}"
      printf 'WG_CORE_ADRESSE=%s\n'      "$WG_CORE_ADRESSE"
      printf 'SERVEUR_ENDPOINT=%s\n'     "$SERVEUR_ENDPOINT"
      printf 'SERVEUR_CLE_PUBLIQUE=%s\n' "$SERVEUR_CLE_PUBLIQUE"
      printf 'AGENT_SECRET=%s\n'         "$AGENT_SECRET"
      printf 'IMG_WG=%s\n'               "${IMG_WG:-consultom/wg:dev}"
      printf 'IMG_WG_AGENT=%s\n'         "${IMG_WG_AGENT:-consultom/wg-agent:dev}"
      printf 'IMG_PROXY_ENROLEMENT=%s\n' "${IMG_PROXY_ENROLEMENT:-consultom/proxy-enrolement:dev}"
    } > "$cible" )
  journal ".env écrit (600) — il porte le secret d'agent, il ne se versionne pas"
}

case "${1:-tout}" in
  sysctls)  sysctls ;;
  parefeu)  poser_parefeu "${2:-${IFACES_PUBLIQUES:-eth0}}" ;;
  montrer-parefeu)
    for _p in ${2:-${IFACES_PUBLIQUES:-eth0}}; do parefeu_public "$_p"; done ;;
  tout)
    verifier_prerequis
    poser_sysctls
    poser_parefeu "${IFACES_PUBLIQUES:-eth0}"
    ecrire_env
    journal "prêt. Reste à poser les secrets de Vault (§2.4) : wg/wg-kits.key et tls/gateway.{crt,key}"
    ;;
  *) echec "argument inconnu « $1 » — attendu : tout, sysctls, parefeu, montrer-parefeu" ;;
esac
