# shellcheck shell=sh
# Pas de shebang : ce fichier est SOURCÉ, jamais exécuté (le shebang
# laisserait croire l'inverse). La directive ci-dessus dit à shellcheck
# quel dialecte lire — sans elle il refuse d'analyser, et le contrôle
# passait inaperçu tant que shellcheck manquait de l'environnement.
# =============================================================================
# Socle commun de l'image `wg` — sourcé, jamais exécuté.
#
# Deux familles y vivent, et une seule raison : ce sont les gestes qu'on ne
# veut écrire QU'UNE FOIS.
#
#   - les interfaces : monter, tenir, REDESCENDRE à l'arrêt (un conteneur wg
#     mort ne laisse pas d'interface orpheline dans le netns hôte), et mourir
#     BRUYAMMENT si une interface tombe — c'est la politique de redémarrage
#     du compose qui relance, jamais une boucle interne qui masquerait un
#     crash-loop (même doctrine que freeradius, lot 5b) ;
#   - les fichiers d'état : une écriture ATOMIQUE dont le mode est posé avant
#     le contenu. Le rôle kit a deux processus qui écrivent dans
#     `/var/lib/controle` (agent d'enrôlement, boucle de marqueurs) : une
#     primitive de sécurité en deux exemplaires finit par diverger.
# =============================================================================

WG_CONF="${WG_CONF:-/etc/wireguard}"
CONTROLE="${CONTROLE:-/var/lib/controle}"

# `journal` est REDÉFINIE par chaque appelant, juste après avoir sourcé ce
# fichier : l'agent d'enrôlement, le watchdog et la boucle de marqueurs
# vivent dans le même conteneur, et on doit pouvoir dire lequel parle.
# Celle-ci est le défaut des scripts de rôle.
journal() { printf 'wg(%s): %s\n' "${WG_ROLE:-?}" "$*" >&2; }

# --- Écriture d'un fichier d'état : atomique, mode et propriétaire compris --
#
# UNE SEULE implémentation pour tout le conteneur (agent d'enrôlement,
# boucle de marqueurs) : c'est une primitive de sécurité — le mode est posé
# sur un fichier VIDE, avant le premier octet de contenu —, et une primitive
# de sécurité qui existe en deux exemplaires finit par diverger.
poser() { # $1 chemin  $2 mode  $3 groupe (vide = aucun chown de groupe)
          # contenu sur l'entrée standard
  _chemin="$1"; _mode="$2"; _groupe="${3:-}"
  _rep="$(dirname "$_chemin")"
  mkdir -p "$_rep" || { journal "mkdir $_rep impossible"; return 1; }
  # Temporaire UNIQUE par appel, jamais dérivé de `$$` : en dash, `$$` garde
  # la valeur du shell père dans un sous-shell, si bien que deux `poser`
  # imbriqués sur le même répertoire se partageraient le MÊME temporaire —
  # le `mv` de l'un arrachant le fichier sous le `cat` de l'autre.
  # Le contenu peut être un secret : le temporaire naît en 600, AVANT la
  # première écriture. Élargir ensuite (640) est sûr ; l'inverse ne l'est pas.
  _tmp="$(umask 077; mktemp "$_rep/.tmp-wg.XXXXXX")" \
    || { journal "création d'un temporaire dans $_rep impossible"; return 1; }
  if ! cat > "$_tmp"; then
    rm -f "$_tmp"; journal "écriture $_chemin impossible"; return 1
  fi
  # Durabilité AVANT publication : « le témoin après ce qu'il atteste » ne
  # vaut que si le contenu a atteint le disque avant le `rename`.
  sync
  if ! chmod "$_mode" "$_tmp"; then
    rm -f "$_tmp"; journal "chmod $_mode $_chemin impossible"; return 1
  fi
  if [ -n "$_groupe" ] && ! chown "0:$_groupe" "$_tmp"; then
    # Jamais de repli silencieux : un fichier de secret sans son groupe est
    # soit illisible par le conteneur qui en dépend, soit trop ouvert.
    rm -f "$_tmp"; journal "chown 0:$_groupe $_chemin impossible"; return 1
  fi
  if ! mv -f "$_tmp" "$_chemin"; then
    rm -f "$_tmp"; journal "rename vers $_chemin impossible"; return 1
  fi
  sync
  return 0
}

# Pose un contenu DÉJÀ EN MAIN, et ne pose RIEN s'il est vide. Un bloc servi
# vide (ou absent d'une réponse plus ancienne) ne doit jamais TRONQUER un
# fichier d'état : `endpoints.txt` vidé, c'est le watchdog sans adresse de
# bascule ; `crl.pem` vidé, c'est FreeRADIUS qui refuse tous les postes.
poser_valeur() { # $1 contenu  $2 chemin  $3 mode  [$4 groupe]
  if [ -z "$1" ]; then
    journal "valeur vide pour $2 — fichier conservé en l'état"
    return 0
  fi
  printf '%s\n' "$1" | poser "$2" "$3" "${4:-}"
}

retirer() { # $1 chemin — suppression durable
  rm -f "$1" || return 1
  sync
  return 0
}

lisible() { [ -r "$1" ] && [ -s "$1" ]; }

# Applique une conf À CHAUD sur une interface DÉJÀ montée — jamais down/up :
# la resynchronisation ne coupe pas le tunnel (annexe 2 §3.5, même exigence
# pour la rotation de clé de passerelles §11.4). Seul propriétaire de ce
# chemin : `monter` ci-dessous et l'agent d'enrôlement l'appellent tous deux.
resynchroniser() { # $1 nom d'interface — montée, conf présente
  # `wg-quick strip` CONSERVE la PrivateKey : le fichier temporaire porte
  # la clé du kit (celle qui ne quitte jamais le kit, annexe 2 §3.2). Il
  # naît donc en 600 (mktemp) et est effacé QUOI QU'IL ARRIVE — même si
  # `wg syncconf` échoue et que set -e nous fait sortir. POSIX sh n'a pas
  # de <(…), d'où le fichier ; il n'a pas de trap RETURN, d'où le nettoyage
  # explicite avant chaque sortie.
  strip="$(mktemp)"
  wg-quick strip "$WG_CONF/$1.conf" > "$strip" \
    || { rm -f "$strip"; return 1; }
  wg syncconf "$1" "$strip" \
    || { rm -f "$strip"; return 1; }
  rm -f "$strip"
}

monter() { # $1 nom d'interface — la conf DOIT exister
  [ -f "$WG_CONF/$1.conf" ] || {
    journal "$WG_CONF/$1.conf absent — rien à monter"
    return 1
  }
  # Idempotent : un restart de conteneur retrouve l'interface déjà posée
  # dans le netns hôte — la re-poser serait un échec, pas une convergence.
  if ip link show "$1" >/dev/null 2>&1; then
    journal "$1 déjà montée — resynchronisation de la conf"
    resynchroniser "$1"
  else
    wg-quick up "$WG_CONF/$1.conf"
  fi
}

descendre() { # $* interfaces, dans l'ordre donné
  for iface in "$@"; do
    wg-quick down "$WG_CONF/$iface.conf" 2>/dev/null \
      || ip link del "$iface" 2>/dev/null || true
  done
}

tenir() { # $* interfaces à surveiller — mort bruyante si l'une disparaît
  while :; do
    sleep 15
    for iface in "$@"; do
      ip link show "$iface" >/dev/null 2>&1 || {
        journal "$iface a disparu — arrêt (le compose relance)"
        # Redescendre les interfaces SURVIVANTES avant de sortir : la
        # promesse « pas d'interface orpheline en netns hôte » vaut aussi
        # sur le chemin de crash, pas seulement sur l'arrêt par signal.
        descendre "$@"
        return 1
      }
    done
  done
}
