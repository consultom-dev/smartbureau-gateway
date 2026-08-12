#!/usr/bin/env bash
# Récupère le contrat OpenAPI du plan de contrôle au commit épinglé.
# Refuse de continuer si le condensat récupéré diverge de l'épingle :
# un contrat qui glisse est un contrat qui ne contraint plus personne.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
epingle="$racine/contrats.epingle"
destination="$racine/.contrat"

[[ -f "$epingle" ]] || { echo "épingle absente : $epingle" >&2; exit 2; }
# shellcheck disable=SC1090
depot=$(grep -E '^depot=' "$epingle" | cut -d= -f2-)
commit=$(grep -E '^commit=' "$epingle" | cut -d= -f2-)
fichier=$(grep -E '^fichier=' "$epingle" | cut -d= -f2-)

[[ ${#commit} -eq 40 ]] || { echo "condensat invalide dans l'épingle : « $commit »" >&2; exit 2; }

rm -rf "$destination"
git clone --quiet --no-checkout --filter=blob:none "$depot" "$destination"
# Checkout DÉTACHÉ sur le commit épinglé — pas `checkout <commit> -- fichier`,
# qui laisse HEAD sur la branche par défaut : la vérification ne passait
# alors que si l'épingle ÉTAIT la tête du dépôt (bogue du lot 0, corrigé
# à l'adoption du contrat au lot 2).
git -C "$destination" checkout --quiet --detach "$commit" 2>/dev/null \
  || { echo "commit épinglé introuvable dans $depot : $commit" >&2; exit 3; }

obtenu=$(git -C "$destination" rev-parse HEAD)
if [[ "$obtenu" != "$commit" ]]; then
  echo "condensat divergent : attendu $commit, obtenu $obtenu" >&2
  exit 3
fi
[[ -f "$destination/$fichier" ]] \
  || { echo "fichier absent au commit épinglé : $fichier" >&2; exit 3; }

echo "contrat récupéré au commit $commit → $destination/$fichier"
