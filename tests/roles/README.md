# `tests/roles/` — la maquette minimale des trois rôles (R-01 … R-06)

**Lot 2, tranche 1.** Fait foi : critère de fini 1 du plan §4 (« les trois
rôles montent leurs interfaces en maquette minimale »), annexe 3 §3.2,
arch. §4.2 et §6.2, annexe 2 §3.1.

Ce banc prouve que l'**image unique** (`WG_ROLE` aiguille — annexe 7 §1)
monte, pour chaque rôle, ce qu'elle doit monter, et **rien d'autre** :

| Cas | Ce qu'il prouve |
|---|---|
| R-01 | image unique : `WG_ROLE` inconnu ou absent → refus bruyant |
| R-02 | serveur : `wg0` monte, `10.100.0.1/24`, écoute `51821`, **feuille** (aucune route) |
| R-03 | passerelle : `wg-kits` (51820) et `wg-core` montent ; la paire `wg-core` **naît localement**, sa publique est écrite |
| R-04 | passerelle : `wg-core.key` en **600** — seule la publique se déclare (§6.1) |
| R-05 | kit : `wg0` monte, **MTU 1360**, `Table = off` → **aucune route par défaut** dans le tunnel (piège 11) |
| R-06 | kit : **aucun** appel `iptables`/`ipset`/`nft` dans son chemin de code (arbitrage Q1) |

## Ce que la maquette NE couvre pas (et pourquoi)

- les **règles netfilter** du rôle passerelle (DROP hub-and-spoke, NAT,
  ipset, `REJECT`) : **lot 4**, banc `tests/netfilter/` ;
- l'**agent d'enrôlement** (machine à états) : **tranche 2**, banc
  `tests/agent-enrolement/` ;
- le **watchdog** (bascule d'endpoint) : **tranche 3**.

Au lot 2, la conf `wg0` du kit est **fournie par la maquette** ; en
production c'est l'agent d'enrôlement qui l'écrit (tranche 2).

## Exécution

Chaque conteneur tourne dans **son propre netns** (pas `host`) : le banc
ne touche pas au réseau de l'hôte. Il faut `NET_ADMIN`, le module noyau
`wireguard` chargé, et `sudo` (création d'interface WireGuard).

```bash
docker build -t consultom/wg:dev docker/wg
sudo ./tests/roles/lancer.sh          # R-01 … R-06
```

Un prérequis manquant (docker, image, module, root) → le banc se déclare
**sauté**, jamais faussement vert (règle du gabarit du lot 0).
