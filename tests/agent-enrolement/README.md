# `tests/agent-enrolement/` — la machine à états, contre le mock

**Lot 2, tranche 2.** Fait foi : **annexe 2 §3.2** (l'état local — fichiers,
modes, propriétaires) et **§3.3** (les états et leurs transitions) ; critère
de fini au plan §4. Le mock du plan de contrôle vit dans
`smartbureau-server/contrats/mock/` et s'épingle **par commit**.

```
USINE     POST /enroler en boucle (backoff 1→15 min)
  ├─ 200 → secret_api, wg0, endpoints, port, repoll, applicatif, domaines,
  │        endpoints.version ; PUIS supprimer usine.json → NOMINAL
  └─ 403 → alerte locale, ET ON CONTINUE D'ESSAYER
NOMINAL   GET /config-kit toutes les 6 h (et au boot), X-Version
  ├─ 304 → rien   ├─ 200 → écritures atomiques, témoin en dernier
  ├─ 403 → SUSPENDU          └─ 401 → IDENTITE_PERDUE
SUSPENDU  re-poll ralenti à 24 h ; 200 → NOMINAL ; 403 → rester
IDENTITE_PERDUE  cadence NOMINALE ; amorce présente → re-enrôler ;
                 porteur relisible → re-poll ; sans porteur → RELIRE
```

## Lancer

```bash
sudo ./tests/agent-enrolement/lancer.py                    # A-01 … A-17
sudo SMARTBUREAU_SERVER=/chemin/vers/smartbureau-server \
     ./tests/agent-enrolement/lancer.py
```

Prérequis : **root** (l'agent d'enrôlement pose des modes et le GID 3000),
`python3`, `curl`, `jq`, et le dépôt `smartbureau-server` à côté (ou
`SMARTBUREAU_SERVER`). **Ni Docker ni module noyau** : c'est ce qui
distingue ce banc de `tests/roles/`, qui exige `sudo` **et** le module
`wireguard` et se déclare **sauté** — jamais vert — quand ils manquent. Un
prérequis absent saute ici aussi.

## Ce que le banc ne prouve pas

Il recette la **machine à états** et les **écritures d'état**, pas
WireGuard : `wg`, `wg-quick` et `ip` sont des doublures qui **journalisent
leurs appels** (`banc.py`). C'est ce journal qui rend vérifiable ce qu'une
interface réelle cacherait — qu'une clé privée n'est générée **qu'une
fois**, et qu'une rotation passe par `wg syncconf` et **jamais** par un
`wg-quick down`. Une quatrième doublure, `mv`, fait échouer la
**publication** d'un fichier désigné : c'est le seul moyen d'observer
l'ORDRE des écritures plutôt que leur seul résultat (A-17). Les
interfaces, elles, sont l'affaire de `tests/roles/`.

**TLS n'est exercé qu'en A-13**, où le banc pose devant le mock une
terminaison TLS et une CA de banc (`openssl` requis, sinon le cas se
déclare sauté). Ailleurs le banc parle en clair, comme le mock. Ce qu'A-13
prouve alors est ce que l'arbitrage Q3 promet, et rien de moins : le repli
joint l'IP en gardant le nom — un agent d'enrôlement qui réécrirait l'URL
verrait le certificat ne plus correspondre —, et la vérification est
réelle, puisque la même requête **échoue** contre une ancre étrangère.

## Les dix-sept cas

| Cas | Ce qu'il prouve | Source |
|---|---|---|
| **A-01** | USINE → NOMINAL : l'ordre des écritures, les modes, les propriétaires ; `endpoints.txt` en IP seules, `repoll.txt` en couples | §3.2, §3.3, invariants 2, 3, 5, 12 |
| **A-02** | la clé du kit naît **avant** le premier POST, et une seule fois — le pivot de l'idempotence | §3.5 ; annexe 1 §4.3 |
| **A-03** | **le cas dur** : réponse perdue **après** traitement, puis rejeu — même /32, rien consommé deux fois | annexe 1, invariant 8 |
| **A-04** | réponse perdue **avant** traitement : rien d'écrit, `usine.json` conservé, la boucle reprend | §3.3 |
| **A-05** | `403` d'enrôlement : alerte locale, et **on continue d'essayer** | §3.3 |
| **A-06** | `200` de re-poll : blocs `pki`/`tls`/`registre`, modes, et `endpoints.version` **en dernier** | §3.2, invariants 3, 11 |
| **A-07** | `304` : le cas courant ne touche **rien** | §3.3 |
| **A-08** | `release_cible` est un **marqueur** — l'agent d'enrôlement n'applique jamais | invariant 6 |
| **A-09** | `403` → SUSPENDU ; le re-poll ne s'arrête jamais et détecte la reprise | invariant 4 |
| **A-10** | `401` → IDENTITE_PERDUE : rien n'est purgé, et la cadence **nominale** est conservée (mesurée) | invariant 4, arbitrage N-1 |
| **A-11** | IDENTITE_PERDUE avec l'amorce : on retente l'enrôlement | arbitrage Q6 |
| **A-12** | IDENTITE_PERDUE sans porteur : **aucune requête n'est émise** | arbitrage Q6 |
| **A-13** | repli sur l'IP : le **nom** est conservé, aucune empreinte épinglée | arbitrage Q3 |
| **A-14** | rotation de clé : `wg syncconf`, jamais `down`/`up` ; le fichier `port` suit | arch. §11.4, arbitrage N4 |
| **A-15** | `500`, temporisation, API morte : on garde tout et on retente | invariant 6 de l'annexe 3 |
| **A-16** | les cadences par défaut du script sont celles du corpus — 6 h / 24 h / 1→15 min (lecture du source) | §3.3 |
| **A-17** | l'**ordre** des écritures : une séquence interrompue laisse `usine.json` en place, et le tour suivant reprend | invariant 2, arbitrage Q2 |

Les cinq modes de coupure du mock sont tous employés : `avant` (A-04),
`apres` (A-03), `erreur_500`, `temporisation` et `ecoute_fermee` (A-15).

## Règle

Chaque cas **cite sa source normative** — un test rouge doit dire quelle
ligne du corpus n'est plus vraie. Un invariant cassé ne se contourne pas :
il rouvre la discussion d'architecture.
