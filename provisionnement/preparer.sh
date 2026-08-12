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
#   1. les sysctls (§2.1) — un routeur qui NAT des milliers de clients
#      sature conntrack avant le CPU, et le forwarding v6 se VERROUILLE
#      (doctrine v4 seul, arch. §9) ;
#   2. le pare-feu public (§2.2) ;
#   3. la vérification des prérequis — module WireGuard, backend nf_tables ;
#   4. le `.env` du nœud, à partir de ce que l'app a rendu à la
#      déclaration (§6.1).
#
# Ce qu'il NE fait PAS : tirer les secrets de Vault. Le chemin froid
# (annexe 5, invariant 4) appartient à l'exploitant, et un script qui
# détient un jeton Vault est un script qu'on ne peut plus laisser tourner
# sans surveillance. Il DIT ce qu'il attend, et refuse de continuer sans.
# =============================================================================
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSCTL_CIBLE="${SYSCTL_CIBLE:-/etc/sysctl.d/60-smartbureau-passerelle.conf}"
APPLIQUER="${APPLIQUER:-1}"        # 0 = montrer sans poser (recette)

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
  sysctls > "$SYSCTL_CIBLE"
  sysctl -p "$SYSCTL_CIBLE" >/dev/null || echec "sysctl -p a échoué sur $SYSCTL_CIBLE"
  journal "sysctls posés dans $SYSCTL_CIBLE"
}

# --- 2. Pare-feu public (§2.2) ----------------------------------------------
# Ce que le nœud accepte DEPUIS L'INTERNET, et rien d'autre : 51820/udp (les
# kits), 443/tcp (le proxy d'enrôlement), 22/tcp (l'administration). Le
# port 80 n'est PAS ouvert — le certificat vient de Vault, aucun challenge
# ACME ne s'exécute ici (§5).
parefeu_public() {
  local pub="${1:-eth0}"
  cat <<CONF
# Pare-feu public — annexe 3 §2.2. Interface : $pub
-A INPUT -i $pub -p udp --dport 51820 -j ACCEPT
-A INPUT -i $pub -p tcp --dport 443   -j ACCEPT
-A INPUT -i $pub -p tcp --dport 22    -j ACCEPT
-A INPUT -i $pub -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i $pub -j DROP
CONF
}

# --- 3. Prérequis ------------------------------------------------------------
verifier_prerequis() {
  command -v docker >/dev/null 2>&1 || echec "docker absent"
  iptables --version 2>/dev/null | grep -q nf_tables \
    || echec "backend netfilter legacy — nf_tables exigé (arch. piège 9)"
  if [ "$APPLIQUER" != "0" ]; then
    modprobe wireguard 2>/dev/null || true
    ip link add essai-wg type wireguard 2>/dev/null \
      || echec "module WireGuard indisponible dans le noyau de l'hôte (§2.1)"
    ip link del essai-wg
  fi
  journal "prérequis vérifiés : docker, nf_tables, module wireguard"
}

# --- 4. Le `.env` du nœud (§6.1) --------------------------------------------
# Les quatre valeurs que l'app REND à la déclaration : l'IP core allouée
# (l'app alloue — arbitrage D4), le secret d'agent remis une fois, le nom
# public à publier en DNS, et l'endpoint du serveur.
ecrire_env() {
  local cible="$RACINE/.env"
  [ -f "$cible" ] && { journal ".env déjà présent — conservé (le secret d'agent ne se réémet pas)"; return 0; }
  for v in GW_ID DOMAINE WG_CORE_ADRESSE SERVEUR_ENDPOINT SERVEUR_CLE_PUBLIQUE AGENT_SECRET; do
    [ -n "${!v:-}" ] || echec "$v non défini — il vient de la déclaration (§6.1) et de Vault (§2.4)"
  done
  ( umask 077
    sed -e "s|^GW_ID=.*|GW_ID=$GW_ID|" \
        -e "s|^DOMAINE=.*|DOMAINE=$DOMAINE|" \
        -e "s|^IFACES_PUBLIQUES=.*|IFACES_PUBLIQUES=${IFACES_PUBLIQUES:-eth0}|" \
        -e "s|^WG_CORE_ADRESSE=.*|WG_CORE_ADRESSE=$WG_CORE_ADRESSE|" \
        -e "s|^SERVEUR_ENDPOINT=.*|SERVEUR_ENDPOINT=$SERVEUR_ENDPOINT|" \
        -e "s|^SERVEUR_CLE_PUBLIQUE=.*|SERVEUR_CLE_PUBLIQUE=$SERVEUR_CLE_PUBLIQUE|" \
        -e "s|^AGENT_SECRET=.*|AGENT_SECRET=$AGENT_SECRET|" \
        "$RACINE/.env.example" > "$cible" )
  journal ".env écrit (600) — il porte le secret d'agent, il ne se versionne pas"
}

case "${1:-tout}" in
  sysctls)  sysctls ;;
  parefeu)  parefeu_public "${2:-${IFACES_PUBLIQUES:-eth0}}" ;;
  tout)
    verifier_prerequis
    poser_sysctls
    journal "pare-feu public à poser sur ${IFACES_PUBLIQUES:-eth0} :"
    parefeu_public "${IFACES_PUBLIQUES:-eth0}"
    ecrire_env
    journal "prêt. Reste à poser les secrets de Vault (§2.4) : wg/wg-kits.key et tls/gateway.{crt,key}"
    ;;
  *) echec "argument inconnu « $1 » — attendu : tout, sysctls, parefeu" ;;
esac
