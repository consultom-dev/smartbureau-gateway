# `tests/watchdog/` — la bascule d'endpoint, et les marqueurs

**Lot 2, tranche 3.** Fait foi : **annexe 2 §3.4** (le watchdog), **§3.4
bis** (la boucle de marqueurs) et **§3.2** (l'état local et ses
propriétaires) ; arch. §6.2 et §7. Critère de fini 3 du plan §4 :
« passerelle simulée muette → bascule d'endpoint ≤ 60 s ;
l'agent d'enrôlement tué → la bascule fonctionne encore ».

```
watchdog   toutes les 30 s : ping -c3 -W2 10.100.0.1
  ├─ répond → RIEN (un tunnel sain ne se reconfigure pas)
  └─ muet   → endpoint suivant d'endpoints.txt, port RELU,
              clé du peer lue sur l'interface (wg show)
marqueurs  toutes les 60 s : etat.json = etat-agent.json (recopié)
                                       + wg show (endpoint, handshake)
```

## Lancer

```bash
./tests/watchdog/lancer.py                 # W-01 … W-12  (~35 s)
```

Prérequis : `sh`, `jq`, `awk`, `curl` (pour W-12). **Ni root, ni Docker,
ni module noyau, ni réseau** — c'est le banc le moins exigeant du dépôt,
parce que le watchdog est le processus le plus simple : deux fichiers, une
interface, aucune décision.

## Comment il observe

`wg`, `ping` et `ip` sont des doublures. Celle de `wg` porte un **état** —
un peer, un endpoint, un handshake — que `wg set` modifie réellement :
c'est ce qui permet de vérifier **une bascule** plutôt que « une commande
a été appelée ». Elle sait aussi **changer le monde entre deux
battements** (le port, la clé du peer) : sans cela, W-04 et W-05
compareraient deux exécutions successives, qui relisent forcément leurs
fichiers — et laisseraient passer précisément la mémorisation que les
arbitrages N4 et Q7 interdisent.

## Les douze cas

| Cas | Ce qu'il prouve | Source |
|---|---|---|
| **W-01** | chemin sain → **rien** ; et le ping vise 10.100.0.1, donc le chemin complet, pas le handshake | §3.4 ; arch. §6.2 |
| **W-02** | passerelle muette → bascule sur l'endpoint suivant | §3.4 ; plan §4 critère 3 |
| **W-03** | rotation **circulaire**, et retour en tête si la liste a été réécrite sous les pieds | arch. §6.2 |
| **W-04** | le **port est relu** à chaque commutation — 51830 pendant une rotation | arbitrage N4 ; arch. §11.4 |
| **W-05** | la **clé du peer** vient de `wg show`, jamais d'une variable ni de `wg0.conf` | arbitrage Q7 |
| **W-06** | la bascule a lieu au **premier** battement qui constate la panne, et tient dans les 60 s — **mesuré à la cadence réelle** (le seul cas long, ~30 s) | plan §4 critère 3 |
| **W-07** | seuls `endpoints.txt` et `port` sont touchés — deux fichiers suffisent | invariant 5 |
| **W-08** | liste absente ou vide → rien, mais **pas de mort** et ce n'est pas silencieux | §3.4 |
| **W-09** | interface absente au premier démarrage → ce n'est pas une panne | §3.3 |
| **W-10** | la boucle de marqueurs publie `etat.json` (644), recopie l'état de l'agent d'enrôlement, et **le watchdog n'y touche jamais** | §3.2, §3.4 bis |
| **W-11** | les marqueurs **n'inventent pas d'état** : absent → `usine`, inexploitable → `inconnu` | §3.4 bis |
| **W-12** | un **vrai agent d'enrôlement lancé puis tué** (SIGKILL) : la bascule fonctionne encore | invariant 5 ; plan §4 critère 3 |

## Règle

Chaque cas **cite sa source normative** — un test rouge doit dire quelle
ligne du corpus n'est plus vraie.
