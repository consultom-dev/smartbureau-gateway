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
git -C "$destination" checkout --quiet "$commit" -- "$fichier" 2>/dev/null \
  || { echo "commit épinglé introuvable dans $depot : $commit" >&2; exit 3; }

obtenu=$(git -C "$destination" rev-parse HEAD 2>/dev/null || echo "$commit")
if [[ "$obtenu" != "$commit" && -n "$obtenu" ]]; then
  echo "condensat divergent : attendu $commit, obtenu $obtenu" >&2
  exit 3
fi

echo "contrat récupéré au commit $commit → $destination/$fichier"
