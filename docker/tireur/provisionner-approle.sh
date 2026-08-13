#!/bin/sh
# =============================================================================
# Provisionne l'accès Vault d'UN tireur (annexe 5 §5.3), à exécuter contre le
# Vault du serveur avec un VAULT_TOKEN d'admin. Un rôle, une policy, un chemin
# — par machine. Rend le `role_id` (à mettre dans la config du tireur) et un
# `secret_id` en réponse ENCAPSULÉE (remis UNE fois ; le tireur le déballe).
#
#   $1 = nom de machine (gateway | factory)
# =============================================================================
set -eu
MACHINE="${1:?usage: provisionner-approle.sh <machine>}"
ICI="$(cd "$(dirname "$0")" && pwd)"

# AppRole activé une fois (idempotent).
vault auth list -format=json 2>/dev/null | grep -q '"approle/"' || vault auth enable approle

# Policy au plus étroit, dérivée du modèle : le seul chemin de CETTE machine.
sed "s/@MACHINE@/$MACHINE/g" "$ICI/policy.hcl.modele" | vault policy write "tireur-$MACHINE" -

# Le rôle : le jeton porte la seule policy de la machine, TTL court et
# renouvelable. secret_id sans expiration ni limite d'usage (le tireur se
# ré-authentifie à chaque tour avec le même — « remis une fois »).
vault write "auth/approle/role/tireur-$MACHINE" \
  token_policies="tireur-$MACHINE" token_ttl=1h token_max_ttl=4h \
  secret_id_ttl=0 secret_id_num_uses=0 >/dev/null

ROLE_ID="$(vault read -field=role_id "auth/approle/role/tireur-$MACHINE/role-id")"
# secret_id en réponse ENCAPSULÉE : un jeton d'enveloppe à TTL court, à usage
# unique. Il voyage à la place du secret ; le tireur le déballe une fois.
WRAP="$(vault write -wrap-ttl=300s -f -field=wrapping_token \
        "auth/approle/role/tireur-$MACHINE/secret-id")"

echo "role_id=$ROLE_ID"
echo "secret_id_encapsule=$WRAP"
echo "# role_id → config du tireur ; jeton encapsulé → son fichier secret_id (remis une fois)."
