#!/bin/sh
# =============================================================================
# tireur — va CHERCHER son certificat dans Vault et l'écrit localement, pour
# le Traefik de sa machine (annexe 5 §5.3). Le central ne POUSSE jamais : il
# ne connaît ni n'atteint ces machines. Partagé par les passerelles et la VM
# usine (annexe 7 §1) ; un secret par machine, un CHEMIN par machine.
#
# Trois propriétés qui ne se négocient pas :
#   - PANNE INERTE : Vault scellé/injoignable ⇒ on GARDE le certificat en
#     place, la machine continue de servir, on réessaie. L'alerte vient de
#     l'approche de l'expiration (métrique, annexe 4), pas de l'échec du tirage.
#   - ATOMIQUE : écriture en temporaire puis rename — jamais de fichier à
#     moitié écrit (une panne TLS plus longue que le renouvellement).
#   - MOINDRE PRIVILÈGE : AppRole, lecture SEULE sur l'unique chemin.
#
# AppRole (annexe 5 §5.3) : role_id dans la config, secret_id remis UNE fois
# au provisionnement en réponse ENCAPSULÉE. On le déballe une fois, on le met
# en cache, et on se ré-authentifie ensuite avec (le jeton d'enveloppe est à
# usage unique — le déballer à chaque tour échouerait).
# =============================================================================
set -eu

: "${VAULT_ADDR:?}" "${TIREUR_CHEMIN:?}" "${TIREUR_ROLE_ID:?}" "${TIREUR_SECRET_ID:?}"
SORTIE="${TIREUR_SORTIE:-/tls}"
GROUPE="${TIREUR_GROUPE:-smartbureau-lecture}"
INTERVALLE="${TIREUR_INTERVALLE:-3600}"
RECHARGE="${TIREUR_RECHARGE:-}"
TOURS="${TIREUR_TOURS:-0}"          # 0 = boucle sans fin ; N = N tours (banc)
CACHE="$SORTIE/.secret_id"          # secret_id déballé, en cache (600)

journal() { printf 'tireur(%s): %s\n' "$TIREUR_CHEMIN" "$*" >&2; }

# secret_id : déballé UNE fois (réponse encapsulée), puis relu du cache.
secret_id() {
  if [ -s "$CACHE" ]; then cat "$CACHE"; return 0; fi
  _sid="$(cat "$TIREUR_SECRET_ID")"
  _clair="$(VAULT_TOKEN="$_sid" vault unwrap -field=secret_id 2>/dev/null)" && _sid="$_clair"
  (umask 077; printf '%s' "$_sid" > "$CACHE")
  printf '%s' "$_sid"
}

# Écriture ATOMIQUE, mode et groupe posés AVANT publication.
ecrire() { # $1 contenu  $2 nom de fichier
  _t="$(umask 077; mktemp "$SORTIE/.tmp.XXXXXX")" || return 1
  printf '%s\n' "$1" > "$_t" || { rm -f "$_t"; return 1; }
  chown "root:$GROUPE" "$_t" 2>/dev/null || journal "groupe $GROUPE indisponible (chown ignoré)"
  chmod 640 "$_t"
  mv -f "$_t" "$SORTIE/$2"
}

tour() {
  _jeton="$(vault write -field=token auth/approle/login \
            role_id="$TIREUR_ROLE_ID" secret_id="$(secret_id)" 2>/dev/null)" || {
    journal "authentification AppRole impossible — certificat conservé, on réessaie"
    return 0
  }
  export VAULT_TOKEN="$_jeton"

  # `kv metadata get` n'accepte pas -field : on lit le JSON et on extrait la
  # version courante (grep suffit — pas de dépendance à jq).
  _meta="$(vault kv metadata get -format=json "$TIREUR_CHEMIN" 2>/dev/null)" || {
    journal "Vault injoignable ou illisible — certificat conservé (panne inerte)"
    return 0
  }
  _vd="$(printf '%s' "$_meta" | grep '"current_version"' | grep -oE '[0-9]+' | head -1)"
  [ -n "$_vd" ] || { journal "version illisible — certificat conservé"; return 0; }
  _vl="$(cat "$SORTIE/.version" 2>/dev/null || echo 0)"
  [ "$_vd" = "$_vl" ] && return 0        # à jour, rien à faire

  _cert="$(vault kv get -field=certificat "$TIREUR_CHEMIN" 2>/dev/null)" || return 0
  _cle="$(vault kv get -field=cle "$TIREUR_CHEMIN" 2>/dev/null)" || return 0
  [ -n "$_cert" ] && [ -n "$_cle" ] || { journal "cert ou clé vide — conservé"; return 0; }

  ecrire "$_cert" cert.pem && ecrire "$_cle" key.pem || { journal "écriture échouée — conservé"; return 0; }
  printf '%s' "$_vd" > "$SORTIE/.version"
  journal "certificat mis à jour (version $_vd)"
  if [ -n "$RECHARGE" ]; then
    sh -c "$RECHARGE" && journal "Traefik rechargé" || journal "rechargement échoué (le cert est en place)"
  fi
}

_n=0
while :; do
  tour
  _n=$((_n + 1))
  { [ "$TOURS" -gt 0 ] && [ "$_n" -ge "$TOURS" ]; } && break
  sleep "$INTERVALLE"
done
