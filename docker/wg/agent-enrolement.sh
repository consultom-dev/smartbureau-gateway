#!/bin/sh
# =============================================================================
# L'agent d'enrôlement du kit — machine à états de l'annexe 2 §3.3.
#
# Il vit dans le conteneur `wg` du kit, en netns hôte (piège 17 : sur le
# bridge `services` il serait enfermé par le fail-closed qu'il doit
# précisément amorcer). Il porte DEUX choses :
#
#   - l'enrôlement (état USINE) : POST /enroler avec le secret d'usine,
#     jusqu'à obtenir une identité ;
#   - le re-poll (état NOMINAL) : GET /config-kit toutes les 6 h, le seul
#     canal descendant du plan de contrôle.
#
# Les deux passent par les PROXYS PUBLICS des passerelles, jamais par le
# tunnel (annexe 2 §7) : c'est ce qui permet à un kit suspendu — donc sans
# tunnel — de détecter sa reprise.
#
# CE QU'IL NE FAIT PAS, et qui compte autant :
#   - il n'invoque JAMAIS netfilter (arbitrage Q1) ;
#   - il n'écrit NI route NI règle (annexe 2 §3.5) — `Table = off`, le
#     routage appartient au plancher `reseau-hote`, l'aiguillage à `parefeu` ;
#   - il n'applique JAMAIS `release_cible` (invariant 6) : il écrit le
#     marqueur, l'updater exécute. Mélanger les deux mettrait une mise à
#     jour logicielle dans la boucle de survie du tunnel ;
#   - il ne purge rien sur une erreur du plan de contrôle : 401, 403, 500
#     ou API morte laissent la configuration en place.
#
# DEUX RÈGLES D'ÉCRITURE, et la recette les vérifie (annexe 2 §3.2, §3.3) :
#   1. chaque fichier est posé ATOMIQUEMENT — temporaire dans le même
#      répertoire, mode posé sur un fichier VIDE avant tout contenu, puis
#      `rename` ;
#   2. le TÉMOIN s'écrit après ce qu'il atteste — `usine.json` n'est
#      supprimé qu'une fois l'enrôlement entier durable, `endpoints.version`
#      n'est écrit qu'une fois tous les blocs du re-poll durables. Une
#      coupure au mauvais moment ne coûte alors qu'un tour de boucle.
#
# PAS DE `set -e` ICI — contrairement aux scripts de rôle. Le métier de cet
# agent est de SURVIVRE aux échecs (4G qui tombe, DNS mort, plan de contrôle
# fâché) : sortir sur le premier code non nul transformerait une coupure
# nominale en crash-loop de conteneur. Chaque appel qui peut échouer est
# donc gardé explicitement.
#
# Dépendances : curl, jq, wg (et `ip` pour savoir si wg0 est montée).
# =============================================================================
set -u

ICI="$(cd "$(dirname "$0")" && pwd)"
# Dans l'image comme dans le dépôt, le socle est au même endroit relatif :
# .../wg/agent-enrolement.sh et .../wg/roles/commun.sh.
. "$ICI/roles/commun.sh"

CONTROLE="${CONTROLE:-/var/lib/controle}"
# WG_CONF vient de commun.sh (défaut /etc/wireguard).
WG_ROLE="${WG_ROLE:-kit}"

USINE="$CONTROLE/usine.json"
SECRET_API="$CONTROLE/secret_api"
ENDPOINTS="$CONTROLE/endpoints.txt"
PORT="$CONTROLE/port"
REPOLL="$CONTROLE/repoll.txt"
VERSION="$CONTROLE/endpoints.version"
ETAT="$CONTROLE/etat-agent.json"
RELEASE="$CONTROLE/release_cible"
APPLICATIF="$CONTROLE/applicatif.json"
DOMAINES="$CONTROLE/domaines.json"
CLE_PRIVEE="$WG_CONF/cle_privee"
WG0="$WG_CONF/wg0.conf"

# Le GID du groupe `smartbureau-lecture` est FIGÉ à 3000 (annexe 2,
# invariant 3) et employé en NUMÉRIQUE : le groupe est créé sur l'hôte par
# `premier-demarrage`, l'image `wg` — commune aux trois rôles — ne le
# connaît pas. Un `chown root:smartbureau-lecture` échouerait dans le
# conteneur ; `chown 0:3000` pose exactement le même propriétaire.
GID_LECTURE=3000

# Les cadences du corpus (annexe 2 §3.3). Surchargeables : la recette
# rejoue la machine à états en quelques secondes, pas en 6 h.
PERIODE_NOMINALE="${AGENT_PERIODE_NOMINALE_S:-21600}"   # 6 h
PERIODE_SUSPENDU="${AGENT_PERIODE_SUSPENDU_S:-86400}"   # 24 h
BACKOFF_MIN="${AGENT_BACKOFF_MIN_S:-60}"                # 1 min
BACKOFF_MAX="${AGENT_BACKOFF_MAX_S:-900}"               # 15 min
# Borne d'exécution : 0 = sans fin, le régime du kit. La recette borne.
TOURS_MAX="${AGENT_TOURS:-0}"
DELAI_HTTP="${AGENT_DELAI_HTTP_S:-30}"
# Le re-poll construit ses URL depuis `repoll.txt` (des NOMS). Le schéma et
# le port n'y figurent pas : le corpus dit HTTPS sur l'étage public
# `gateway`. La recette, elle, parle au mock en clair sur un port éphémère.
SCHEMA="${AGENT_REPOLL_SCHEMA:-https}"
PORT_REPOLL="${AGENT_REPOLL_PORT:-}"

BAC="$(mktemp -d)"
REPONSE="$BAC/reponse"
TRACE="$BAC/trace"
CORPS="$BAC/corps.json"        # corps de POST /enroler — porte le secret d'usine
PORTEUR="$BAC/porteur.conf"    # config curl — porte le secret d'API
CODE=""
backoff="$BACKOFF_MIN"

nettoyer() { rm -rf "$BAC"; }
trap nettoyer EXIT
trap 'nettoyer; exit 0' TERM INT

# Redéfinit celle de commun.sh : trois processus dans le même conteneur.
journal() { printf 'wg(agent-enrolement): %s\n' "$*" >&2; }

# `poser`, `poser_valeur`, `retirer` et `lisible` viennent de `commun.sh` —
# une seule implémentation de l'écriture atomique pour tout le conteneur.
#
# CONVENTION DE NOMMAGE — POSIX sh n'a pas de `local` : toute variable de
# fonction est GLOBALE. Elles sont donc préfixées d'un `_` et l'espace de
# noms est cloisonné par fonction : `commun.sh` réserve `_chemin _mode
# _groupe _rep _tmp` ; `appeler` réserve `_url _ip _rc _hote` ; `tour_usine`
# réserve `_cle _pub` ; `tour_repoll` réserve `_entree _version _servi` ;
# `ecrire_wg0` réserve `_cle_wg0` ; `etat_ecrire` réserve `_hs _ep _rendu` ;
# `deduire_etat` réserve `_memorise` ;
# `appliquer_config_kit` réserve `_adresse _endpoint` ; `endpoint_courant`
# réserve `_ep`. Les deux fichiers sensibles du bac
# (`$CORPS`, `$PORTEUR`) naissent en 600 et meurent avec le `trap`.
# Une fonction n'écrit JAMAIS dans le préfixe d'une autre — c'est la seule
# chose qui rende sûr d'appeler l'une depuis l'autre.

# --- etat-agent.json (annexe 2 §3.2) ---------------------------------------
# UN SEUL PROPRIÉTAIRE PAR FICHIER. L'agent d'enrôlement possède
# `etat-agent.json` ; `etat.json` — celui que lit `sante` — appartient à la
# boucle de marqueurs (60 s, tranche 3), qui y recopie l'état d'ici. Deux
# écrivains atomiques sur un même fichier ne se complètent pas : le dernier
# `rename` efface les champs de l'autre, et l'agent d'enrôlement perdrait
# SUSPENDU ou IDENTITE_PERDUE à chaque battement de 60 s.
#
# Le vocabulaire est celui du tableau du §3.2 — `enrole` y nomme l'état
# NOMINAL du §3.3. `wg show` n'est interrogé que si l'interface existe : au
# premier démarrage elle n'existe pas encore, et ce n'est pas une anomalie.
etat_ecrire() { # $1 etat  $2 code HTTP (ou "-")  $3 détail libre
  _hs=0
  _ep=""
  if ip link show wg0 >/dev/null 2>&1; then
    _hs="$(wg show wg0 latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')"
    _ep="$(wg show wg0 endpoints 2>/dev/null | awk 'NR==1{print $2}')"
  fi
  case "${_hs:-}" in ''|*[!0-9]*) _hs=0 ;; esac
  # `poser_valeur` et non `poser` : un `jq` en échec produirait un flux VIDE,
  # et `poser` publierait un `etat-agent.json` de zéro octet — l'état
  # mémorisé serait perdu, donc SUSPENDU et IDENTITE_PERDUE avec lui.
  _rendu="$(jq -n --arg etat "$1" --arg code "$2" --arg detail "${3:-}" \
        --arg endpoint "${_ep:-}" --argjson hs "$_hs" \
        --arg horodatage "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     '{etat:$etat, code_config_kit:$code, detail:$detail,
       endpoint:$endpoint, dernier_handshake:$hs, horodatage:$horodatage}')" || return 1
  poser_valeur "$_rendu" "$ETAT" 644
}

# --- HTTP : le nom d'abord, l'IP en repli SANS perdre le nom ---------------
# `curl` sort 6 sur un échec de RÉSOLUTION, et sur lui seul. C'est le seul
# cas où le corpus autorise le repli sur l'IP (annexe 2 §3.3) — une
# connexion refusée ou un TLS refusé ne sont PAS des échecs de résolution et
# ne déclenchent aucun repli.
#
# Le repli garde le nom : `--resolve <hote>:<port>:<ip>` court-circuite le
# résolveur et RIEN d'autre. SNI et vérification de chaîne restent ceux du
# nom, la vérification TLS reste ordinaire, et le système n'épingle nulle
# part (arbitrage Q3 — une empreinte figée à l'atelier serait fausse au
# premier renouvellement du wildcard `*.gateway.<domaine>.tld`).
#
# `printf '%s\n'` PARTOUT, jamais `echo` : le `echo` de dash interprète les
# séquences d'échappement, et un `\n` de PEM dans un corps JSON en ressort
# en saut de ligne littéral — le JSON devient invalide et les blocs `pki` et
# `tls` disparaissent en silence. Même raison pour laquelle les réponses
# sont lues DIRECTEMENT depuis leur fichier, sans détour par une variable.
hote_de_url() { printf '%s\n' "$1" | sed -e 's,^[a-z][a-z]*://,,' -e 's,[:/].*$,,'; }
port_de_url() {
  _hp="$(printf '%s\n' "$1" | sed -e 's,^[a-z][a-z]*://,,' -e 's,/.*$,,')"
  case "$_hp" in
    *:*) printf '%s\n' "${_hp##*:}" ;;
    *)   case "$1" in http://*) printf '80\n' ;; *) printf '443\n' ;; esac ;;
  esac
}

appeler() { # $1 url  $2 ip de repli (vide si aucune)  puis args curl
  _url="$1"; _ip="${2:-}"; shift 2
  CODE="$(curl -sS --max-time "$DELAI_HTTP" -o "$REPONSE" -w '%{http_code}' \
               "$@" "$_url" 2>"$TRACE")"
  _rc=$?
  if [ "$_rc" -eq 6 ] && [ -n "$_ip" ]; then
    _hote="$(hote_de_url "$_url")"
    journal "résolution de $_hote impossible — repli sur $_ip, nom conservé"
    CODE="$(curl -sS --max-time "$DELAI_HTTP" -o "$REPONSE" -w '%{http_code}' \
                 --resolve "$_hote:$(port_de_url "$_url"):$_ip" \
                 "$@" "$_url" 2>"$TRACE")"
    _rc=$?
  fi
  [ "$_rc" -eq 0 ] \
    || journal "appel $_url en échec (curl $_rc) : $(tail -1 "$TRACE" 2>/dev/null)"
  return "$_rc"
}

# --- La clé du kit : née AVANT le premier POST (annexe 2 §3.5) -------------
# C'est le pivot de l'idempotence. Le rejeu après réponse perdue n'est un
# `200` de même identité que si le kit rappelle avec la MÊME clé publique
# (annexe 1 §4.3) : une clé régénérée à chaque tentative transformerait
# chaque coupure 4G d'atelier en « secret consommé par une autre clé
# publique », c'est-à-dire en kit mort.
cle_privee() {
  if ! lisible "$CLE_PRIVEE"; then
    wg genkey | poser "$CLE_PRIVEE" 600 || return 1
    journal "clé privée du kit générée et persistée (600) — avant tout appel"
  fi
  cat "$CLE_PRIVEE"
}

# --- Configuration WireGuard (arch. §6.2, annexe 2 §3.5) -------------------
# `AllowedIPs = 0.0.0.0/0` VA AVEC `Table = off` — jamais l'un sans l'autre
# (piège 11) : le /0 porte l'internet centralisé, le `Table = off` empêche
# wg-quick de poser la route par défaut qui basculerait TOUT le kit dans le
# tunnel. Le fichier porte la clé privée du kit : 600.
ecrire_wg0() { # $1 adresse/32  $2 clé publique passerelles  $3 endpoint  $4 port
  # La clé est lue AVANT le tube : `cle_privee` peut avoir à la générer,
  # donc à appeler `poser` — un `poser` dans le tube d'un autre `poser`. Et
  # une substitution vide écrirait ici une `PrivateKey = ` en rendant 0,
  # c'est-à-dire une conf inutilisable sur laquelle `tour_usine`
  # supprimerait quand même `usine.json`.
  _cle_wg0="$(cle_privee)"
  [ -n "$_cle_wg0" ] || { journal "clé privée indisponible — wg0.conf non écrite"; return 1; }
  { printf '[Interface]\n'
    printf 'PrivateKey = %s\n' "$_cle_wg0"
    printf 'Address = %s\n' "$1"
    printf 'MTU = 1360\n'
    printf 'Table = off\n'
    printf '\n[Peer]\n'
    printf 'PublicKey = %s\n' "$2"
    printf 'AllowedIPs = 0.0.0.0/0\n'
    printf 'Endpoint = %s:%s\n' "$3" "$4"
    printf 'PersistentKeepalive = 25\n'
  } | poser "$WG0" 600
}

adresse_courante() { sed -n 's/^Address *= *//p' "$WG0" 2>/dev/null | head -1; }

# L'endpoint que porte l'INTERFACE — pas celui de la conf : c'est le
# watchdog qui l'a posé, et il ne réécrit jamais `wg0.conf`.
endpoint_courant() {
  ip link show wg0 >/dev/null 2>&1 || return 0
  _ep="$(wg show wg0 endpoints 2>/dev/null | awk 'NR==1{print $2}')"
  case "${_ep:-}" in ''|'(none)') return 0 ;; esac
  printf '%s\n' "${_ep%:*}"
}

# À chaud seulement : si wg0 est montée, on resynchronise (jamais down/up —
# la rotation ne coupe pas le tunnel). Si elle ne l'est pas, on ne monte
# rien : c'est le rôle kit qui monte, l'agent d'enrôlement n'écrit que la conf.
appliquer_wg0() {
  if ip link show wg0 >/dev/null 2>&1; then
    if resynchroniser wg0; then
      journal "wg0 resynchronisée (wg syncconf, sans coupure)"
    else
      journal "resynchronisation de wg0 en échec — la conf est écrite, le rôle kit reprendra"
    fi
  fi
}

# --- Le bloc `passerelles`, commun à /enroler et /config-kit ---------------

# Le bloc est au même chemin dans les deux réponses (`/enroler` et
# `/config-kit`) : une seule fonction, lue directement dans $REPONSE.
ecrire_passerelles() {
  poser_valeur "$(jq -r '.passerelles.endpoints[]?' "$REPONSE")" "$ENDPOINTS" 644 || return 1
  poser_valeur "$(jq -r '.passerelles.port // 51820' "$REPONSE")" "$PORT" 644 || return 1
  # `repoll` en COUPLES « nom IP » (arbitrage L4) : le nom est la voie
  # normale — seule vérifiable en TLS —, l'IP le seul repli si la résolution
  # échoue.
  poser_valeur "$(jq -r '.passerelles.repoll[]? | "\(.hote) \(.ip)"' "$REPONSE")" \
               "$REPOLL" 644 || return 1
  return 0
}

# --- USINE : POST /enroler (annexe 2 §3.3, annexe 1 §4.3) ------------------

tour_usine() {
  _cle="$(cle_privee)"
  [ -n "$_cle" ] || { journal "clé privée indisponible — rien à tenter"; return 1; }
  _pub="$(printf '%s\n' "$_cle" | wg pubkey)"
  # Le secret d'usine passe par un FICHIER (600), jamais par l'argv : le
  # conteneur `wg` est en netns hôte, et `/proc/<pid>/cmdline` est lisible
  # bien plus largement qu'un fichier. Même raison que l'interdiction de le
  # journaliser (annexe 3 §5).
  ( umask 077
    jq -n --arg s "$(jq -r '.secret' "$USINE")" --arg c "$_pub" \
          '{secret:$s, cle_publique:$c}' > "$CORPS" ) || return 1

  # Chaque URL du tableau `enrolement`, dans l'ordre ; l'IP de repli est
  # celle du couple `repli` qui porte le même hôte. Le `while` tourne dans
  # un sous-shell (il est en bout de tube) : le verdict passe par des
  # marqueurs, pas par des variables.
  rm -f "$BAC/enrole" "$BAC/refus"
  jq -r '.enrolement[]?' "$USINE" | while read -r url; do
    _hote="$(hote_de_url "$url")"
    _ip="$(jq -r --arg h "$_hote" '.repli[]? | select(.hote == $h) | .ip' "$USINE" | head -1)"
    appeler "$url" "$_ip" -X POST -H 'Content-Type: application/json' -d "@$CORPS"
    case "$CODE" in
      200) : > "$BAC/enrole"; break ;;
      403)
        # Fichier d'usine annulé, ou secret consommé par une AUTRE clé
        # publique (vol probable). Bruyant, mais NON terminal : on continue
        # d'essayer — le journal du serveur, lui, voit la rafale.
        journal "403 sur $url — fichier d'usine annulé ou volé ; on continue d'essayer"
        : > "$BAC/refus" ;;
      *) : ;;
    esac
  done

  if [ ! -f "$BAC/enrole" ]; then
    if [ -f "$BAC/refus" ]; then
      etat_ecrire usine 403 "enrôlement refusé — fichier d'usine annulé ou volé"
    else
      etat_ecrire usine "-" "aucune URL d'enrôlement joignable"
    fi
    return 1
  fi

  # L'ORDRE qui suit est normatif (annexe 2 §3.3) et se lit d'une traite :
  # tout ce qui constitue l'identité, PUIS le témoin. `usine.json` part en
  # dernier — c'est le point de non-retour, et le seul ordre qui rende une
  # coupure rejouable (annexe 1, invariant 8).
  poser_valeur "$(jq -r '.secret_api' "$REPONSE")" "$SECRET_API" 640 "$GID_LECTURE" || return 1
  ecrire_wg0 "$(jq -r '.adresse' "$REPONSE")" \
             "$(jq -r '.passerelles.cle_publique' "$REPONSE")" \
             "$(jq -r '.passerelles.endpoints[0]' "$REPONSE")" \
             "$(jq -r '.passerelles.port // 51820' "$REPONSE")" || return 1
  ecrire_passerelles || return 1
  # `applicatif` porte un secret de client Keycloak : 640, jamais le `.env`
  # (invariant 12 — arbitrage N3). `domaines` n'en porte pas : 644.
  poser_valeur "$(jq -c '.applicatif // empty' "$REPONSE")" "$APPLICATIF" 640 "$GID_LECTURE" || return 1
  poser_valeur "$(jq -c '.domaines // empty' "$REPONSE")" "$DOMAINES" 644 || return 1
  poser_valeur "$(jq -r '.version // empty' "$REPONSE")" "$VERSION" 644 || return 1
  journal "enrôlé : $(jq -r '.kit_id' "$REPONSE") — identité durable"
  # `usine.json` EN DERNIER : le point de non-retour (invariant 2). Si la
  # suppression échoue — montage passé en lecture seule, carte SD en
  # détresse — l'enrôlement n'en est pas moins RÉUSSI : le signaler comme
  # un échec ferait rejouer `/enroler` à chaque battement, et chaque rejeu
  # réémet un `secret_api` en invalidant le précédent (annexe 1 §6.1).
  # C'est `deduire_etat` qui retentera la seule chose qui reste à faire.
  if retirer "$USINE"; then
    journal "usine.json supprimé (invariant 2)"
  else
    journal "ALERTE : usine.json NON supprimé — le secret d'usine survit sur le kit"
  fi
  appliquer_wg0
  etat_ecrire enrole 200 "enrôlement réussi"
  return 0
}

# --- NOMINAL / SUSPENDU / IDENTITE_PERDUE : GET /config-kit ----------------

tour_repoll() { # $1 état d'entrée
  _entree="$1"
  if ! lisible "$SECRET_API"; then
    # Arbitrage Q6 : sans porteur, AUCUNE requête n'est émise. Elle ne
    # pourrait pas réussir, et une rafale de 401 est indiscernable d'une
    # attaque dans le journal du serveur (annexe 1 §2.6). Ce qui peut
    # changer est LOCAL : on relit le fichier au battement suivant.
    journal "secret_api absent ou illisible — aucune requête émise, relecture au prochain battement"
    etat_ecrire identite_perdue "-" "secret_api absent ou illisible — ré-enrôlement en atelier"
    return 1
  fi
  # Le porteur passe par un fichier de configuration curl (600) — même
  # raison que le secret d'usine ci-dessus : hors de l'argv.
  ( umask 077
    printf 'header = "Authorization: Bearer %s"\n' \
           "$(sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' "$SECRET_API" | head -1)" \
      > "$PORTEUR" ) || return 1
  _version=""
  [ -r "$VERSION" ] && _version="$(cat "$VERSION")"

  _servi=""
  if [ -r "$REPOLL" ]; then
    while read -r hote ip; do
      [ -n "${hote:-}" ] || continue
      _url="$SCHEMA://$hote${PORT_REPOLL:+:$PORT_REPOLL}/config-kit"
      appeler "$_url" "${ip:-}" --config "$PORTEUR" -H "X-Version: $_version"
      case "$CODE" in 200|304|401|403) _servi="$CODE"; break ;; *) : ;; esac
    done < "$REPOLL"
  else
    journal "repoll.txt absent — aucune adresse de re-poll"
  fi

  case "$_servi" in
    304)
      # Le cas nominal, quatre fois par jour : RIEN n'est touché.
      etat_ecrire enrole 304 "à jour"
      return 0 ;;
    200)
      appliquer_config_kit || return 1
      etat_ecrire enrole 200 "configuration appliquée"
      return 0 ;;
    403)
      # Suspendu ou révoqué — le kit ne distingue pas les deux, et ne se
      # « débranche » jamais tout seul (invariant 4). Depuis
      # IDENTITE_PERDUE, un 403 est une INFORMATION : le porteur vaut, donc
      # le kit était suspendu (arbitrage Q6).
      [ "$_entree" = "identite_perdue" ] \
        && journal "403 depuis IDENTITE_PERDUE — le porteur vaut : le kit est suspendu"
      etat_ecrire suspendu 403 "kit suspendu ou révoqué — re-poll ralenti à 24 h"
      return 0 ;;
    401)
      # Identité perdue, PAS suspension : cadence nominale conservée, rien
      # n'est purgé (arbitrage N-1, invariant 4).
      etat_ecrire identite_perdue 401 "porteur inconnu du serveur — cadence nominale conservée"
      return 0 ;;
    *)
      # Plan de contrôle injoignable, 500, temporisation : on garde tout et
      # on retentera. Un agent sans plan de contrôle ne purge rien.
      journal "aucune réponse exploitable — configuration conservée, nouvel essai au prochain battement"
      etat_ecrire "$_entree" "-" "plan de contrôle injoignable"
      return 1 ;;
  esac
}

appliquer_config_kit() {
  if [ "$(jq -r 'has("passerelles")' "$REPONSE")" = "true" ]; then
    ecrire_passerelles || return 1
    _adresse="$(adresse_courante)"
    if [ -n "$_adresse" ]; then
      # L'ENDPOINT COURANT EST PRÉSERVÉ s'il figure encore dans la liste
      # servie. Reprendre `endpoints[0]` à chaque `200` ramènerait le kit
      # sur la passerelle nominale et défairait la bascule du watchdog —
      # or l'architecture §7 promet « les kits restent où ils sont, pas de
      # retour automatique ». Le rééquilibrage est un acte du serveur, qui
      # pousse des listes réordonnées, jamais un effet de bord du re-poll.
      _endpoint="$(endpoint_courant)"
      if [ -z "$_endpoint" ] \
         || ! jq -e --arg e "$_endpoint" '.passerelles.endpoints[]? | select(. == $e)' \
                 "$REPONSE" >/dev/null 2>&1; then
        _endpoint="$(jq -r '.passerelles.endpoints[0]' "$REPONSE")"
      fi
      # Une rotation de clé de passerelles (§11.4) n'est qu'un 200 dont
      # `passerelles` a changé : « aucun mécanisme dédié ». On réécrit le
      # [Peer] et on resynchronise — sans jamais redescendre l'interface.
      ecrire_wg0 "$_adresse" \
                 "$(jq -r '.passerelles.cle_publique' "$REPONSE")" \
                 "$_endpoint" \
                 "$(jq -r '.passerelles.port // 51820' "$REPONSE")" || return 1
      appliquer_wg0
    else
      journal "wg0.conf sans adresse — [Peer] non réécrit (le /32 vient de l'enrôlement)"
    fi
  fi

  # `release_cible` : un MARQUEUR, rien de plus (invariant 6).
  # L'agent d'enrôlement n'applique jamais une release — l'updater
  # (annexe 7 §4) exécute. Mélanger les deux mettrait une mise à jour
  # logicielle dans la boucle de survie du tunnel.
  poser_valeur "$(jq -r '.release_cible // empty' "$REPONSE")" "$RELEASE" 644 || return 1

  # PKI d'itinérance : ancres + CRL. FreeRADIUS et le Keycloak local suivent
  # le CHANGEMENT DE FICHIER (annexe 6) : rien n'est rechargé ici.
  poser_valeur "$(jq -r '.pki.ancres[]?' "$REPONSE")" "$CONTROLE/pki/ancres.pem" 644 || return 1
  poser_valeur "$(jq -r '.pki.crl // empty' "$REPONSE")" "$CONTROLE/pki/crl.pem" 644 || return 1

  # Certificat de FLOTTE : la clé est partagée par les 10 000 kits (§12.5),
  # d'où le 640 et l'interdiction de la mettre dans une image ou une
  # sauvegarde.
  poser_valeur "$(jq -r '.tls.cert // empty' "$REPONSE")" "$CONTROLE/tls/local.crt" 644 || return 1
  poser_valeur "$(jq -r '.tls.cle // empty' "$REPONSE")" "$CONTROLE/tls/local.key" 640 "$GID_LECTURE" || return 1

  # Identité Harbor du kit : 600 root, car SEUL dockerd la lit, par le
  # credential helper — aucun conteneur non privilégié n'y a affaire
  # (invariant 11). Rien à recharger : le helper lit le fichier au prochain
  # tirage (annexe 2 §3.6).
  poser_valeur "$(jq -c '.registre // empty' "$REPONSE")" "$CONTROLE/registre/auth.json" 600 || return 1

  # LE TÉMOIN, EN DERNIER : tant que `endpoints.version` n'est pas écrit, le
  # prochain re-poll redemande tout. L'écrire plus tôt figerait le kit sur
  # une configuration partielle, que le 304 rendrait définitive.
  poser_valeur "$(jq -r '.version // empty' "$REPONSE")" "$VERSION" 644 || return 1
  return 0
}

# --- La boucle -------------------------------------------------------------
# L'état ne se mémorise pas dans une variable : il se DÉDUIT des fichiers à
# chaque tour. Un agent d'enrôlement redémarré retrouve donc exactement
# l'état du kit, et `usine.json` présent veut toujours dire « il reste un
# enrôlement à faire » — y compris quand on y arrive depuis IDENTITE_PERDUE,
# ce qui est précisément la première branche de l'arbitrage Q6.
deduire_etat() {
  _memorise="$(jq -r '.etat // "usine"' "$ETAT" 2>/dev/null)"
  case "$_memorise" in usine|enrole|suspendu|identite_perdue) : ;; *) _memorise=usine ;; esac
  if [ -f "$USINE" ]; then
    # `usine.json` présent ET un enrôlement déjà abouti (porteur lisible,
    # état mémorisé `enrole` ou `suspendu`) : seule la SUPPRESSION a
    # échoué. Rejouer `/enroler` ici réémettrait un `secret_api` à chaque
    # battement en invalidant le précédent (annexe 1 §6.1) — une boucle de
    # brûlage silencieuse. On reste dans l'état atteint ; la suppression
    # est retentée au tour suivant.
    case "$_memorise" in
      enrole|suspendu) lisible "$SECRET_API" && { printf '%s\n' "$_memorise"; return; } ;;
      *) : ;;
    esac
    # Tous les autres cas mènent à USINE — `identite_perdue` compris :
    # c'est la première branche de l'arbitrage Q6, « l'amorce est encore
    # là, on retente l'enrôlement ».
    printf 'usine\n'; return
  fi
  if ! lisible "$SECRET_API"; then printf 'identite_perdue\n'; return; fi
  case "$_memorise" in
    suspendu|identite_perdue) printf '%s\n' "$_memorise" ;;
    *) printf 'enrole\n' ;;
  esac
}

# Le point de non-retour, retenté : un `usine.json` qui survit à un
# enrôlement abouti est un secret d'usine vivant sur le kit — exactement ce
# qu'un voleur cherche (invariant 2). On ne rejoue pas l'enrôlement pour
# autant : on ne retente que la suppression.
finir_enrolement() {
  [ -f "$USINE" ] || return 0
  if retirer "$USINE"; then
    journal "usine.json enfin supprimé (suppression retardée — invariant 2)"
  else
    journal "ALERTE : usine.json toujours pas supprimé — le secret d'usine survit sur le kit"
  fi
}

journal "démarrage — contrôle=$CONTROLE conf=$WG_CONF (annexe 2 §3.3)"
tour=0
while :; do
  tour=$((tour + 1))
  etat="$(deduire_etat)"
  case "$etat" in
    usine)
      if tour_usine; then
        backoff="$BACKOFF_MIN"
        # Au sortir de l'enrôlement le kit n'a ni `pki`, ni `tls`, ni
        # identité de registre : c'est le premier re-poll qui les remet.
        # L'attendre 6 h laisserait FreeRADIUS, le Traefik local et dockerd
        # sans leur matière — « et au boot » vaut aussi ici.
        attente=1
      else
        attente="$backoff"
        backoff=$((backoff * 2))
        [ "$backoff" -gt "$BACKOFF_MAX" ] && backoff="$BACKOFF_MAX"
      fi ;;
    suspendu)
      finir_enrolement
      tour_repoll suspendu
      attente="$PERIODE_SUSPENDU" ;;
    *)
      # `enrole` (NOMINAL) et `identite_perdue` partagent la CADENCE
      # NOMINALE. C'est tout l'arbitrage N-1 : une identité perdue est une
      # panne, pas une décision d'administration — le ralenti de 24 h y
      # transformerait une carte SD fatiguée en kit définitivement perdu.
      finir_enrolement
      tour_repoll "$etat"
      attente="$PERIODE_NOMINALE" ;;
  esac

  if [ "$TOURS_MAX" -ne 0 ] && [ "$tour" -ge "$TOURS_MAX" ]; then break; fi
  if [ "$attente" -gt 0 ]; then sleep "$attente"; fi
done
journal "arrêt après $tour tour(s)"
