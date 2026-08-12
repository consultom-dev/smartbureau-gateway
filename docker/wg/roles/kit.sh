#!/bin/sh
# =============================================================================
# Rôle KIT — wg0, agent d'enrôlement, watchdog, marqueurs
# (annexe 2 §3 ; arch. §6.2).
#
# Quatre processus, une hiérarchie stricte :
#   - wg0 : la conf est écrite par l'agent d'enrôlement à l'enrôlement
#     (jamais provisionnée, jamais versionnée — elle porte la clé privée du
#     kit). Au premier démarrage elle n'existe pas encore : on l'attend.
#   - l'agent d'enrôlement : machine à états annexe 2 §3.3 — il vit ICI,
#     en netns hôte (piège 17 : sur le bridge services il serait enfermé
#     par le fail-closed qu'il doit amorcer), et il porte aussi le
#     re-poll, le canal descendant.
#   - le watchdog : bascule d'endpoint (30 s), INDÉPENDANT de
#     l'agent d'enrôlement (annexe 2, invariant 5) — il ne lit qu'endpoints.txt et
#     port, et la bascule fonctionne agent d'enrôlement mort ;
#   - la boucle de marqueurs (60 s) : elle publie etat.json pour `sante`,
#     et n'observe que — trois cadences, aucune n'attend les autres.
#
# Ce script n'écrit NI route NI règle (annexe 2 §3.5) : Table = off dans la
# conf, le routage appartient au plancher reseau-hote, l'aiguillage à
# parefeu. Et il n'invoque JAMAIS netfilter (arbitrage Q1).
# =============================================================================
set -eu
. /usr/local/lib/wg/roles/commun.sh

AGENT="/usr/local/lib/wg/agent-enrolement.sh"
WATCHDOG="/usr/local/lib/wg/watchdog.sh"
MARQUEURS="/usr/local/lib/wg/marqueurs.sh"
PIDS=""

lancer_si_present() { # $1 chemin — l'absence n'empêche pas une maquette
  [ -x "$1" ] || return 0
  "$1" &
  PIDS="$PIDS $!"
}

arreter() {
  for p in $PIDS; do kill -TERM "$p" 2>/dev/null || true; done
  descendre wg0
  exit 0
}
trap arreter TERM INT

# L'agent d'enrôlement d'abord : c'est lui qui écrit wg0.conf au premier
# démarrage (état USINE). Son absence n'empêche pas une maquette de monter
# une conf déjà écrite — d'où la garde `-x` plutôt qu'un échec.
lancer_si_present "$AGENT"

# La boucle de marqueurs tourne DÈS MAINTENANT, avant même wg0 : un kit
# bloqué en USINE est précisément celui dont on veut lire l'état.
lancer_si_present "$MARQUEURS"

# Attendre la conf (premier démarrage : l'enrôlement peut prendre le temps
# du backoff 1→15 min — on ne borne pas, l'état se lit dans etat.json).
until [ -f "$WG_CONF/wg0.conf" ]; do
  sleep 5
done
monter wg0
journal "wg0 montée (Table = off, MTU 1360 — arch. §6.2)"

# Le watchdog APRÈS wg0 : basculer l'endpoint d'une interface absente n'a
# pas de sens ; et il survit seul ensuite (invariant 5).
lancer_si_present "$WATCHDOG"

tenir wg0
