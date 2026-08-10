# `tests/agent-passerelle/` — la boucle de 30 s

**Lot 4.** Fait foi : **annexe 3 §4 et §8**. Rejoué contre le mock du plan
de contrôle (`smartbureau-server/contrats/mock/`, épinglé par commit).

## Les quatre cas durs

| Cas | Ce qu'il prouve | Invariant |
|---|---|---|
| **P-12** | pose manuelle d'un peer, redémarrage du conteneur, `wg-quick` rejoué → **reconvergence sans doublon** | 8 — le diff porte sur `wg show` |
| **P-13** | 401 puis API morte → peers **et** ipset inchangés, backoff, alerte | 6 — un agent de passerelle sans plan de contrôle ne purge rien |
| **P-14** | drapeau `internet` retiré d'un kit dans `/peers` → `ipset del` du **seul** /32 concerné | §4.1 — synchronisation par écart |
| **P-15** | aucun accès aux fichiers de clés, aucune modification de netfilter attribuable pendant un cycle complet | 7 — l'agent de passerelle ne détient aucune clé |

## Pourquoi ces quatre-là

Ce sont les cas où une implémentation « raisonnable » se trompe :
mémoriser la liste des peers au lieu de la relire (P-12), « nettoyer »
sur 401 par souci de cohérence (P-13), reconstruire l'ipset entièrement
au lieu d'appliquer l'écart (P-14), donner à l'agent de passerelle la clé
partagée « pour simplifier » (P-15).

Le mock doit pouvoir répondre 304, 200 avec version changée, 401, et
**cesser de répondre** — c'est ce dernier comportement qui distingue une
API morte d'un refus.

`POST /etat-tunnels` s'envoie **au même battement**, en delta depuis le
dernier envoi.
