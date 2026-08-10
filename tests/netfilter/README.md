# `tests/netfilter/` — les cas P-01 … P-20

**Lot 4.** Les cas s'écrivent sur le **gabarit partagé** du lot 0, logé
aujourd'hui dans `smartbureau-server/outillage/tests-netfilter/` (il
déménagera vers `smartbureau-factory` au lot 6). `cas/` reçoit un fichier
par invariant : `P-04-kit-vers-kit-refuse.cas`.

| Famille | Cas |
|---|---|
| pose et retrait | P-01 à froid, P-02 idempotence, P-03 `trap` à l'arrêt |
| hub-and-spoke | **P-04 kit ↔ kit refusé** (et la démonstration inverse : retirer la règle ⇒ ça passe) |
| chemin nominal | P-05 kit → serveur, source NATée vue par le serveur |
| **ordre** | P-06 le `REJECT` final **en dernière position** — un `-I` mal placé couperait toute la flotte |
| ipset | P-07 kit autorisé, P-08 kit non autorisé, P-09 elle plafonne et n'aiguille pas |
| deux verrous | P-10 `FORWARD` et `INPUT` |
| sonde | P-11 isolation retirée ⇒ sonde rouge même wg-core parfait |
| agent de passerelle | P-12 reconvergence sans doublon, P-13 401 sans purge, P-14 ipset par écart, P-15 aucune clé, aucune règle |
| doctrine v4 | P-16 verrou v6 |
| proxy | P-17 deux routes et 404, P-18 indépendance des tunnels |
| refus de poser | P-19 backend `legacy` |
| hôte | P-20 pare-feu public |

## Trois points à connaître avant d'écrire le premier cas

- **Backend nf_tables obligatoire** : en `legacy`, **tous** les tests
  seraient faussement verts (piège 9).
- **Deux divergences sont bloquantes** pour P-01 et P-04, signalées par
  les LISEZMOI du gabarit : la lecture exacte de « poser en dernier » face
  au couple `-C` puis `-I` (une des trois lectures couperait la flotte), et
  la distinction `DROP`/`REJECT` non observable en l'état. À trancher
  **dans le corpus** avant d'écrire ces cas.
- **Le chemin des scripts vu par `$SUJET`** reste à arrêter (réserve **R2**
  de `docs/arborescences.md`), ainsi que le mode de consommation du
  gabarit par ce dépôt (réserve **R3**).
