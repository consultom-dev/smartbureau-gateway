#!/bin/sh
# =============================================================================
# L'agent de passerelle (annexe 3 §4).
#
# Toutes les 30 s, dans cet ordre : `GET /peers`, puis `POST /etat-tunnels`.
# Il APPLIQUE une décision prise ailleurs, et c'est tout son pouvoir.
#
# CE QU'IL NE FAIT PAS, et qui définit son cloisonnement (§4.2) :
#   - il ne détient AUCUNE clé — ni wg-kits, ni wg-core. Celui qui détient
#     les clés (`wireguard`) n'a, lui, aucun canal sortant ;
#   - il ne pose AUCUNE règle de pare-feu — il ne reçoit même pas
#     `IFACES_PUBLIQUES` (arbitrage Q10 : un agent de passerelle qui
#     connaît les interfaces de sortie est un agent qu'on finira par faire
#     poser des règles) ;
#   - il ne relaie RIEN du trafic des kits.
#
# TROIS INVARIANTS QU'IL PORTE :
#
#   6. **Un agent sans plan de contrôle ne purge rien.** Un `401`, un `500`
#      ou une API morte laissent les peers EN PLACE : la passerelle
#      continue de servir ses kits. L'inverse ferait d'une panne du serveur
#      une panne de flotte — c'est la règle la plus importante d'ici.
#   8. **Le diff porte sur `wg show`**, jamais sur une liste mémorisée :
#      c'est ce qui rend équivalents un redémarrage de conteneur, une pose
#      manuelle et une reprise après crash. Idem pour l'ipset, dont le diff
#      porte sur `ipset list`.
#   5. **Tous les peers sur toutes les passerelles** : la table servie est
#      la table appliquée, sans filtrage local — une table partielle fait
#      échouer les bascules, et le kit se fait jeter en silence.
#
# Pas de `set -e` : son métier est de survivre au plan de contrôle absent.
# Dépendances : curl, jq, wg, ipset.
# =============================================================================
set -u

API="${API:?API non définie — https://api.server.<domaine>.tld}"
GW_ID="${GW_ID:?GW_ID non défini}"
AGENT_SECRET="${AGENT_SECRET:?AGENT_SECRET non défini (tiré de Vault au provisionnement)}"

IFACE_KITS="${IFACE_KITS:-wg-kits}"
IPSET_INTERNET="${IPSET_INTERNET:-internet_ok}"
ETAT="${AGENT_ETAT:-/var/lib/wg-agent}"
VERSION="$ETAT/peers.version"
# La table SERVIE, mémorisée. Elle n'est pas « la liste » que l'invariant 8
# proscrit — le diff porte toujours sur `wg show`. Elle est la CIBLE, et il
# faut la garder : sans elle, un `304` (le cas nominal, 99 % des tours) ne
# donne rien à comparer, et une interface remontée à vide après un
# `wg-quick` rejoué à la main resterait vide pour toujours.
PEERS="$ETAT/peers.json"

PERIODE="${AGENT_PERIODE_S:-30}"
BACKOFF_MAX="${AGENT_BACKOFF_MAX_S:-300}"
DELAI_HTTP="${AGENT_DELAI_HTTP_S:-20}"
TOURS_MAX="${AGENT_TOURS:-0}"          # 0 = sans fin, le régime du nœud
# Fractionnement du delta (arbitrage A8) : la borne de 32 Ko vise les corps
# de REQUÊTE. Au-delà, on envoie PLUSIEURS requêtes — jamais un corps
# amputé. Un état de flotte silencieusement tronqué produirait exactement
# la panne que l'annexe 4 appelle « alerter sur l'absence » : des kits
# vivants comptés comme silencieux, au moment où la supervision sert.
LOT_ETAT="${AGENT_LOT_ETAT:-200}"
case "$PERIODE"   in ''|*[!0-9]*) PERIODE=30 ;; esac
case "$TOURS_MAX" in ''|*[!0-9]*) TOURS_MAX=0 ;; esac
case "$LOT_ETAT"  in ''|*[!0-9]*|0) LOT_ETAT=200 ;; esac
case "$BACKOFF_MAX" in ''|*[!0-9]*) BACKOFF_MAX=300 ;; esac
case "$DELAI_HTTP"  in ''|*[!0-9]*) DELAI_HTTP=20 ;; esac

BAC="$(mktemp -d)"
REPONSE="$BAC/reponse"
PORTEUR="$BAC/porteur.conf"
backoff="$PERIODE"

nettoyer() { rm -rf "$BAC"; }
trap nettoyer EXIT
trap 'nettoyer; exit 0' TERM INT

journal() { printf 'wg-agent: %s\n' "$*" >&2; }

mkdir -p "$ETAT" 2>/dev/null

# Le secret d'agent passe par un fichier de configuration curl (600), pas
# par l'argv : `/proc/<pid>/cmdline` est lisible bien plus largement.
( umask 077
  printf 'header = "Authorization: Bearer %s"\nheader = "X-Gw-Id: %s"\n' \
         "$(printf '%s' "$AGENT_SECRET" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')" \
         "$GW_ID" > "$PORTEUR" ) || exit 1

# --- 1. GET /peers ----------------------------------------------------------

recuperer_peers() {
  _version=""
  [ -r "$VERSION" ] && _version="$(cat "$VERSION")"
  CODE="$(curl -sS --max-time "$DELAI_HTTP" -o "$REPONSE" -w '%{http_code}' \
               --config "$PORTEUR" -H "X-Version: $_version" \
               "$API/peers" 2>/dev/null)"
  [ -n "$CODE" ] || CODE="000"
}

# Le DIFF, sur `wg show` — jamais sur ce que l'agent de passerelle CROIT
# avoir posé (invariant 8). La table servie vient de `$PEERS`, l'état réel
# de l'interface : c'est leur écart qu'on applique, à chaque tour.
appliquer_peers() {
  _servis="$BAC/servis"; _poses="$BAC/poses"
  # `jq` en commande SÉPARÉE, jamais en tête de tube : en `sh` sans
  # `pipefail`, un `cmd | sort > f || return 1` teste `sort`, pas `cmd`. Un
  # corps illisible (page d'erreur d'un intermédiaire, réponse tronquée)
  # produirait alors une table servie VIDE — et la boucle de retraits
  # purgerait toute la passerelle. Un plan de contrôle bavard mais cassé
  # est pire qu'un plan de contrôle muet (invariant 6).
  jq -r '.peers[]? | "\(.cle_publique) \(.allowed_ips)"' "$PEERS" > "$BAC/servis.brut" \
    || { journal "table servie illisible — RIEN n'est appliqué, la table en place reste"; return 1; }
  sort < "$BAC/servis.brut" > "$_servis"
  # `wg show <iface> dump` : première ligne = l'interface, puis un peer par
  # ligne (clé, psk, endpoint, allowed-ips, …).
  wg show "$IFACE_KITS" dump 2>/dev/null | awk 'NR>1 {print $1, $4}' \
    | sort > "$_poses"

  _echecs=0 _n=0 _r=0
  # `comm` sur deux fichiers triés : un passage, zéro fork par ligne. Le
  # `grep` par ligne coûtait 26 s par battement à 10 000 kits — pour un
  # battement de 30 s, et un contrat qui promet « appliqué en ≤ 30 s ».
  comm -13 "$_poses" "$_servis" > "$BAC/a-poser"
  while read -r cle ips; do
    [ -n "${cle:-}" ] || continue
    if wg set "$IFACE_KITS" peer "$cle" allowed-ips "$ips"; then
      _n=$((_n + 1))
    else
      journal "pose du peer ${cle%"${cle#????????}"}… en échec"
      _echecs=$((_echecs + 1))
    fi
  done < "$BAC/a-poser"

  # Retraits : ce qui est posé et n'est plus servi. Le retrait porte sur la
  # CLÉ seule — un peer dont le /32 a changé vient d'être mis à jour.
  cut -d' ' -f1 "$_servis" | sort -u > "$BAC/cles-servies"
  cut -d' ' -f1 "$_poses"  | sort -u > "$BAC/cles-posees"
  comm -13 "$BAC/cles-servies" "$BAC/cles-posees" > "$BAC/a-retirer"
  while read -r cle; do
    [ -n "${cle:-}" ] || continue
    if wg set "$IFACE_KITS" peer "$cle" remove; then
      _r=$((_r + 1))
    else
      _echecs=$((_echecs + 1))
    fi
  done < "$BAC/a-retirer"

  [ "$_n" -gt 0 ] || [ "$_r" -gt 0 ] \
    && journal "$_n peer(s) posé(s) ou mis à jour, $_r retiré(s)"
  # Un `wg set` en échec — l'interface n'existe pas encore, couplage lâche
  # (§4.1) — doit REMONTER : sinon la version serait mémorisée, le tour
  # suivant recevrait un 304, et la table resterait à moitié posée.
  [ "$_echecs" -eq 0 ] || { journal "$_echecs opération(s) en échec — application INCOMPLÈTE"; return 1; }
  return 0
}

# L'ipset se synchronise PAR ÉCART, comme les peers, et sur `ipset list` —
# jamais sur une liste mémorisée. Elle PLAFONNE, elle n'aiguille pas
# (invariant 1) : on n'y touche que pour refléter le drapeau `internet`.
appliquer_ipset() {
  ipset list "$IPSET_INTERNET" >/dev/null 2>&1 || {
    # C'est le conteneur `wg` qui la crée (§3.2). Absente, on ne la crée
    # pas à sa place : deux propriétaires pour un même objet, c'est la
    # panne au premier `compose stop`.
    journal "ipset $IPSET_INTERNET absente — le conteneur wg ne l'a pas encore créée"
    return 0
  }
  jq -r '.peers[]? | select(.internet == true) | .allowed_ips' "$PEERS" \
    > "$BAC/internet.brut" \
    || { journal "table servie illisible — l'ipset n'est PAS touchée"; return 1; }
  sed 's,/.*,,' < "$BAC/internet.brut" | sort -u > "$BAC/internet-servis"
  ipset list "$IPSET_INTERNET" | awk '/^[0-9]+\./ {print $1}' \
    | sort -u > "$BAC/internet-poses"

  comm -13 "$BAC/internet-poses" "$BAC/internet-servis" > "$BAC/ipset-a-ajouter"
  comm -23 "$BAC/internet-poses" "$BAC/internet-servis" > "$BAC/ipset-a-retirer"
  while read -r ip; do
    [ -n "${ip:-}" ] || continue
    ipset add "$IPSET_INTERNET" "$ip" -exist
  done < "$BAC/ipset-a-ajouter"
  while read -r ip; do
    [ -n "${ip:-}" ] || continue
    ipset del "$IPSET_INTERNET" "$ip"
  done < "$BAC/ipset-a-retirer"
  return 0
}

# --- 2. POST /etat-tunnels --------------------------------------------------

remonter_etat() {
  # Delta depuis le dernier envoi : les peers dont le handshake a bougé.
  _vu="$ETAT/handshakes"
  wg show "$IFACE_KITS" dump 2>/dev/null \
    | awk 'NR>1 && $5 > 0 {print $1, $5, $6, $7}' | sort > "$BAC/handshakes" || return 0
  [ -s "$BAC/handshakes" ] || return 0
  if [ -r "$_vu" ]; then
    comm -23 "$BAC/handshakes" "$_vu" > "$BAC/delta"
  else
    cp "$BAC/handshakes" "$BAC/delta"
  fi
  [ -s "$BAC/delta" ] || return 0

  # FRACTIONNER, jamais tronquer (arbitrage A8).
  _total="$(wc -l < "$BAC/delta")"
  _envoyes=0
  _lot=1
  while [ "$_envoyes" -lt "$_total" ]; do
    sed -n "$((_envoyes + 1)),$((_envoyes + LOT_ETAT))p" "$BAC/delta" > "$BAC/tranche"
    jq -Rn --arg gw "$GW_ID" --argjson ts "$(date +%s)" \
       '[inputs | split(" ")] as $l
        | {gw: $gw, horodatage: $ts,
           kits: [$l[] | {cle_publique: .[0], dernier_handshake: (.[1]|tonumber),
                          rx: (.[2]|tonumber), tx: (.[3]|tonumber)}]}' \
       < "$BAC/tranche" > "$BAC/corps.json" || return 1
    CODE="$(curl -sS --max-time "$DELAI_HTTP" -o /dev/null -w '%{http_code}' \
                 -X POST --config "$PORTEUR" -H 'Content-Type: application/json' \
                 -d "@$BAC/corps.json" "$API/etat-tunnels" 2>/dev/null)"
    case "${CODE:-000}" in
      204|200) : ;;
      *)
        # Un envoi raté ne purge rien et ne mémorise rien : le delta
        # repartira au tour suivant (invariant 6).
        journal "POST /etat-tunnels tranche $_lot → ${CODE:-000} — rien de mémorisé, nouvel essai au prochain tour"
        return 1 ;;
    esac
    _envoyes=$((_envoyes + LOT_ETAT))
    _lot=$((_lot + 1))
  done
  [ "$_total" -gt "$LOT_ETAT" ] \
    && journal "delta de $_total lignes envoyé en $((_lot - 1)) requêtes (fractionné, arbitrage A8)"
  # Mémorisé SEULEMENT après succès complet.
  cp "$BAC/handshakes" "$_vu"
  return 0
}

# --- La boucle --------------------------------------------------------------

journal "démarrage — api=$API gw=$GW_ID période=${PERIODE}s (annexe 3 §4.1)"
tour=0
while :; do
  tour=$((tour + 1))
  attente="$PERIODE"

  recuperer_peers
  case "$CODE" in
    304|200)
      backoff="$PERIODE"
      if [ "$CODE" = "200" ]; then
        # Le corps est VALIDÉ avant de remplacer la table servie : un
        # `200` illisible ne doit pas effacer la cible.
        if jq -e '.peers' "$REPONSE" >/dev/null 2>&1; then
          cp "$REPONSE" "$PEERS"
        else
          journal "200 au corps illisible — table servie CONSERVÉE, rien n'est purgé"
        fi
      fi
      # ON APPLIQUE À CHAQUE TOUR, `304` COMPRIS. Le `304` dit « la table
      # servie n'a pas changé », pas « l'interface est conforme » : un
      # `wg-quick` rejoué à la main, un conteneur redémarré, un peer effacé
      # laissent une interface qui diverge de la table sans que le serveur
      # en sache rien. C'est tout le sens de l'invariant 8 — et sans cela,
      # une passerelle remontée à vide ne servirait plus JAMAIS un kit.
      if [ -r "$PEERS" ]; then
        if appliquer_peers && appliquer_ipset; then
          # La version n'est mémorisée QU'APRÈS application réussie : la
          # mémoriser avant ferait répondre 304 au tour suivant sur une
          # table que l'on n'a pas su poser.
          [ "$CODE" = "200" ] && jq -r '.version // empty' "$REPONSE" > "$VERSION"
        else
          journal "application incomplète — version NON mémorisée, on redemandera tout"
          rm -f "$VERSION"
        fi
      fi ;;
    401)
      # Secret révoqué, ou nœud retiré. ON NE PURGE RIEN (invariant 6) :
      # une passerelle sans plan de contrôle continue de servir ses kits.
      journal "ALERTE 401 sur /peers — secret d'agent révoqué ou passerelle retirée ; les peers RESTENT en place"
      attente="$backoff"
      backoff=$((backoff * 2))
      [ "$backoff" -gt "$BACKOFF_MAX" ] && backoff="$BACKOFF_MAX" ;;
    *)
      journal "/peers → ${CODE:-000} — plan de contrôle injoignable ; les peers RESTENT en place"
      attente="$backoff"
      backoff=$((backoff * 2))
      [ "$backoff" -gt "$BACKOFF_MAX" ] && backoff="$BACKOFF_MAX" ;;
  esac

  remonter_etat

  if [ "$TOURS_MAX" -ne 0 ] && [ "$tour" -ge "$TOURS_MAX" ]; then break; fi
  [ "$attente" -gt 0 ] && sleep "$attente"
done
journal "arrêt après $tour tour(s)"
