# smartbureau-gateway

Dépôt des **passerelles** SmartBureau (rôle `gateway`) — les nœuds
relais WireGuard — et maison de l'**image `wg` unique** servant les
trois rôles.

## Prérequis de session

Le corpus normatif vit dans `consultom-dev/smartbureau-server` sous
`docs/architecture/`. **Attacher ce dépôt** à toute session de travail
ici.

## Ce que ce dépôt contient (cible, annexe 7 §1)

Compose passerelle, **l'image `wg`** (paramétrée par
`WG_ROLE=serveur|passerelle|kit` — elle embarque aussi le watchdog et
l'agent d'enrôlement du rôle kit), `wg-agent`, `proxy-enrolement`,
`tireur` (partagé passerelles / VM usine).

## Références normatives

Architecture §5 (passerelles), §6.2 (conteneur `wg` du kit), §7
(bascule), §11 (sécurisation, rotation) ; **annexe 3** (la spec de ce
dépôt) ; annexe 2 §3 (machine à états de l'agent d'enrôlement, état
local). Lots du plan : **2** (image `wg`), **4** (passerelle complète).

## Règles de travail

1. **La documentation fait foi** ; divergence → corriger le corpus
   d'abord (PR sur `smartbureau-server`), le code ensuite.
2. **Langue** : français partout ; lexique normatif §16 (« agent »
   toujours qualifié : agent de passerelle / agent d'enrôlement).
3. **Les invariants sont des tests** : annexe 3 §8 (12 invariants) en
   tests netfilter et tests de boucle d'agent.

## Invariants à ne jamais casser ici

- **L'image `wg` reste unique.** Une seule chaîne de construction
  multi-arch, le rôle en variable d'environnement — ne jamais la
  re-fragmenter en images par rôle (annexe 7 §1).
- **Le DROP `wg-kits → wg-kits` est le hub-and-spoke** — les
  `AllowedIPs` ne l'assurent pas (annexe 3, invariant 2).
- **`FORWARD` et `INPUT` sont deux verrous distincts** (invariant 4).
- **L'agent ne détient aucune clé** ; celui qui détient les clés
  (`wireguard`) n'a aucun canal sortant (doctrine annexe 3).
- **Un agent sans plan de contrôle ne purge rien** : 401 ou API morte →
  les peers restent, la passerelle continue de servir (invariant 6).
- **Le diff porte sur `wg show`**, jamais sur une liste mémorisée
  (invariant 8).
- **L'ipset `internet_ok` plafonne, elle n'aiguille pas** — ne jamais
  la vider « pour dépanner » (invariant 1).
- **Le proxy d'enrôlement ne dépend pas des tunnels** : il sert
  précisément les kits qui n'en ont pas (invariant 9). Deux routes,
  tout le reste en 404.
- **Sans état** : aucun volume de données de valeur — la panne se
  répare en redéployant, jamais en restaurant (doctrine annexe 3).

## Interdits concrets

- Pas de troisième route sur le proxy d'enrôlement.
- Pas de résolution DNS dans le chemin du tunnel : endpoints en IP ;
  la surcharge `api.` se pose en `extra_hosts` dans le compose, sur
  chaque conteneur qui parle au plan machine (invariant 3).
- Backend netfilter **nf_tables** obligatoire — les scripts refusent de
  poser sinon (piège 9 de l'architecture).
- Pas de tag d'image mobile ; base Debian épinglée (définie dans
  `smartbureau-factory`).

## Commandes

À compléter aux lots 2 et 4 (tests des trois rôles, tests d'agent).
