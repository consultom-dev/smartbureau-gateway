# smartbureau-gateway — les passerelles, et l'image `wg`

Dépôt des **passerelles** SmartBureau (rôle `gateway`) — les nœuds relais
WireGuard — et **maison de l'image `wg` unique**, celle qui sert les trois
rôles du système (annexe 7 §1).

**Le corpus normatif n'est pas ici** : il vit dans
`consultom-dev/smartbureau-server`, sous `docs/architecture/`. Toute
session de travail sur ce dépôt **attache ce dépôt en plus**. Voir
`CLAUDE.md`.

## Ce dépôt porte du code qui s'exécute ailleurs

C'est la conséquence la plus contre-intuitive du découpage par rôle, et
celle qu'on défera par mégarde si on ne l'écrit pas :

| Ce qui vit ici | S'exécute sur |
|---|---|
| image `wg`, rôle `passerelle` | les passerelles |
| image `wg`, rôle `serveur` | le serveur central |
| image `wg`, rôle `kit` — **watchdog et agent d'enrôlement compris** | les 10 000 kits |
| `tireur` | les passerelles **et** la VM usine |

L'image `wg` a **une seule maison** : une seule chaîne de construction
multi-arch, un seul jeu de tests, **un condensat identique partout**. Le
découpage par rôle ne doit jamais la re-fragmenter.

## L'arborescence

| Répertoire | Ce qui y vit | Lot |
|---|---|---|
| `docker/wg/` | l'image unique, `WG_ROLE=serveur\|passerelle\|kit` | 2, puis 4 |
| `docker/wg-agent/` | pull `/peers`, diff sur `wg show`, `POST /etat-tunnels` | 4 |
| `docker/proxy-enrolement/` | **deux routes**, et rien d'autre | 4 |
| `docker/tireur/` | Vault Agent — passerelles et VM usine | 5a |
| `provisionnement/` | sysctls, module, pare-feu public, secrets de Vault | 4 |
| `tests/netfilter/cas/` | les cas **P-01 … P-20** | 4 |
| `tests/agent-enrolement/` | la machine à états rejouée contre le mock | 2 |
| `tests/agent-passerelle/` | la boucle : 401 sans purge, idempotence | 4 |

À la racine, au lot 4 : `docker-compose.yml` et `.env.example`.

**Jamais versionné** : `wg/` (clé partagée et paire wg-core), `tls/`
(wildcard `*.gateway` tiré de Vault), `.env`. Détail :
`docs/arborescences.md` §8 du dépôt `smartbureau-server`.

## Sans état, par construction

Une passerelle ne détient **aucune donnée qu'on regretterait de perdre** :
sa configuration est tirée (Vault au provisionnement, `/peers` en
continu). La panne d'un nœud se répare en déployant le même compose
ailleurs, **jamais en restaurant une sauvegarde** — et cela se vérifie
d'un coup d'œil : le compose n'a aucun volume de données.
