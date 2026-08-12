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
  local pub="$1" src
  printf '%s\n' "-i $pub -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
  printf '%s\n' "-i $pub -p udp --dport ${WG_KITS_PORT:-51820} -j ACCEPT"
  printf '%s\n' "-i $pub -p tcp --dport 443 -j ACCEPT"
  # 22/tcp est « administration SEULE » dans la table du §2.2, par
  # opposition explicite à « toute l'Internet » des deux lignes
  # précédentes. Sans `-s`, chaque passerelle exposerait SSH à l'Internet.
  for src in ${ADMIN_SSH:-}; do
    printf '%s\n' "-i $pub -p tcp -s $src --dport 22 -j ACCEPT"
  done
  printf '%s\n' "-i $pub -j DROP"
}

parefeu_public() {   # la forme LISIBLE, pour l'inspection et la recette
  local pub="${1:-eth0}"
  echo "# Pare-feu public — annexe 3 §2.2. Interface : $pub"
  parefeu_regles "$pub" | sed 's/^/-A INPUT /'
}

# La séquence est-elle complète ET dans l'ordre ? Le fourre-tout doit être
# la DERNIÈRE règle d'INPUT qui parle de cette interface : tout ce qui le
# suit est inatteignable, et un `-C` ne sait pas le dire.
parefeu_conforme() {
  local pub="$1" ligne derniere
  while read -r ligne; do
    [ -n "$ligne" ] || continue
    # shellcheck disable=SC2086
    $IPT -C INPUT $ligne 2>/dev/null || return 1
  done < <(parefeu_regles "$pub")
  derniere="$($IPT -S INPUT 2>/dev/null | grep -e "-i $pub " | tail -n 1)"
  case "$derniere" in
    *"-i $pub -j DROP"*) return 0 ;;
    *) return 1 ;;
  esac
}

poser_parefeu() {
  local pub_liste="${1:-eth0}" pub ligne
  if [ "$APPLIQUER" = "0" ]; then
    journal "pare-feu public (non appliqué, APPLIQUER=0) :"
    for pub in $pub_liste; do parefeu_public "$pub"; done
    return 0
  fi
  [ -n "${ADMIN_SSH:-}" ] \
    || echec "ADMIN_SSH non défini — le §2.2 dit « 22/tcp : administration SEULE ». Poser la ou les plages d'administration (CIDR séparés par des espaces) ; ouvrir 22 à l'Internet « en attendant » est un provisoire qui survit à la mise en production"

  for pub in $pub_liste; do
    if parefeu_conforme "$pub"; then
      journal "pare-feu public déjà conforme sur $pub"
      continue
    fi
    # LA SÉQUENCE ENTIÈRE, comme au §3.2 et pour la même raison : remettre
    # en queue le seul port manquant le placerait DERRIÈRE le fourre-tout —
    # présent, compté, vérifiable, et mort. Le jour où §6.4 ouvre 51830
    # pour wg-kits2, rejouer ce script sur les nœuds déjà provisionnés
    # produirait exactement cela, sur toute la flotte.
    #
    # Barrage d'abord : la fenêtre de reconstruction est FERMÉE. Un script
    # tué au milieu laisse l'interface publique close, jamais ouverte.
    $IPT -C INPUT -i "$pub" -j DROP 2>/dev/null \
      || $IPT -I INPUT 1 -i "$pub" -j DROP \
      || echec "pare-feu public : barrage impossible à poser sur $pub"

    while read -r ligne; do
      [ -n "$ligne" ] || continue
      # shellcheck disable=SC2086
      $IPT -D INPUT $ligne 2>/dev/null || true
    done < <(parefeu_regles "$pub")

    while read -r ligne; do
      [ -n "$ligne" ] || continue
      # shellcheck disable=SC2086
      $IPT -A INPUT $ligne || echec "pare-feu public : « $ligne » refusée sur $pub"
    done < <(parefeu_regles "$pub")

    # Le barrage posé en tête n'appartient pas à la séquence : la dernière
    # règle vient d'être posée en queue, celui-ci doit partir.
    while [ "$($IPT -S INPUT 2>/dev/null | grep -ce "^-A INPUT -i $pub -j DROP$" || true)" -gt 1 ]; do
      # `-D` retire la PREMIÈRE occurrence : le barrage, jamais le
      # fourre-tout qui vient d'être reposé en queue.
      $IPT -D INPUT -i "$pub" -j DROP || echec "pare-feu public : barrage impossible à retirer sur $pub"
    done

    # VÉRIFIER APRÈS AVOIR POSÉ — présence ET position. Le fourre-tout est
    # la règle qui ferme ; s'il manque, tout ce qui écoute sur l'hôte est
    # joignable depuis l'Internet, et s'il n'est pas dernier, ce sont les
    # ouvertures qui ne servent à rien.
    parefeu_conforme "$pub" \
      || echec "pare-feu public : séquence non conforme sur $pub après la pose ($($IPT -S INPUT | grep -e "-i $pub " | tr '\n' '|'))"
    journal "pare-feu public posé sur $pub (${WG_KITS_PORT:-51820}/udp, 443/tcp ouverts ; 22/tcp depuis $ADMIN_SSH ; tout le reste fermé)"
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
ConditionPathExists=$RACINE/provisionnement/preparer.sh

[Service]
Type=oneshot
RemainAfterExit=yes
# Les guillemets ne sont PAS décoratifs : sans eux, une liste de deux
# interfaces perd la seconde (« Invalid environment assignment »), et le
# nœud repart au boot avec elle GRANDE OUVERTE — la panne de Q13, différée
# d un redémarrage.
Environment="IFACES_PUBLIQUES=$pub_liste"
Environment="ADMIN_SSH=$ADMIN_SSH"
Environment="WG_KITS_PORT=${WG_KITS_PORT:-51820}"
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
verifier_backend() {
  iptables --version 2>/dev/null | grep -q nf_tables \
    || echec "backend netfilter legacy — nf_tables exigé (arch. piège 9)"
}

# Les interfaces de sortie publique DOIVENT exister. netfilter accepte un
# nom d'interface inexistant sans broncher : les règles seraient posées,
# comptées, vérifiables — et jamais atteintes. Sur une VM en `ens3`
# provisionnée avec le défaut `eth0`, la sortie internet de toute la
# flotte servie serait morte, en silence.
verifier_interfaces() {
  local pub
  for pub in ${IFACES_PUBLIQUES:-eth0}; do
    ip link show "$pub" >/dev/null 2>&1 \
      || echec "interface de sortie publique « $pub » inexistante — poser IFACES_PUBLIQUES (§7, arbitrage Q10)"
  done
}

verifier_prerequis() {
  command -v docker >/dev/null 2>&1 || echec "docker absent"
  verifier_backend
  verifier_interfaces

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
  # LES TROIS SÉPARÉMENT. Une garde sur leur CONCATÉNATION est satisfaite
  # par une seule : un nœud partirait avec `wg` par condensat et les deux
  # autres en `:dev`, ce que le dépôt interdit.
  if [ "${AUTORISER_IMAGES_DEV:-0}" != "1" ]; then
    local manquantes=""
    for v in IMG_WG IMG_WG_AGENT IMG_PROXY_ENROLEMENT; do
      [ -n "${!v:-}" ] || manquantes="$manquantes $v"
    done
    [ -z "$manquantes" ] \
      || echec "images non fixées :$manquantes — sourcer le release.env de la release (pas de tag mobile, §6.1), ou poser AUTORISER_IMAGES_DEV=1 pour une maquette"
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
  parefeu)
    # C'est le SEUL chemin exécuté au démarrage. Il refait donc les mêmes
    # vérifications que la pose initiale : un backend legacy poserait des
    # règles muettes (piège 9), et une interface renommée par l'hyperviseur
    # produirait des règles présentes et jamais atteintes.
    IFACES_PUBLIQUES="${2:-${IFACES_PUBLIQUES:-eth0}}"
    verifier_interfaces
    verifier_backend
    poser_parefeu "$IFACES_PUBLIQUES" ;;
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
