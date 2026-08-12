# `tests/netfilter/` — les invariants de la passerelle, en netns réel

**Lot 4.** Fait foi : **annexe 3 §3.2** (ce que pose la passerelle) et
**§8** (les douze invariants) ; arbitrages **Q8** (l'ordre de pose), **Q9**
(le silence contre le refus) et **Q10** (`IFACES_PUBLIQUES`).

Les cas vivent ici — **décision R3** : le dépôt qui détient le script
testé détient ses cas. Le **gabarit**, lui, vit dans
`smartbureau-server/outillage/tests-netfilter/` et s'épingle par
condensat, comme le contrat OpenAPI.

```bash
sudo SMARTBUREAU_SERVER=/chemin/vers/smartbureau-server \
     ./tests/netfilter/lancer.sh                  # P-01 … P-08
sudo SMARTBUREAU_SERVER=… ./tests/netfilter/lancer.sh --cas P-03 --garder
```

Prérequis : **root**, `ip netns`, `iptables` (backend nf_tables), `ipset`,
et `nc` pour les cas qui injectent des paquets. Un prérequis manquant fait
un cas **sauté**, jamais vert.

## Les huit cas

| Cas | Ce qu'il prouve | Source |
|---|---|---|
| **P-01** | à froid : les sept règles, et leur **ordre** — le fourre-tout en dernier, les trois ACCEPT avant lui | §3.2, arbitrage Q8 |
| **P-02** | trois poses ne posent qu'une fois ; une règle effacée revient **à sa place**, et un barrage oublié est retiré | §3.2, arbitrage Q8 |
| **P-03** | **paquets réels** : kit ↔ kit refusé (et le compteur dit que c'est le DROP qui a tranché), kit → cœur permis, sortie internet **par ipset** dans les deux sens | invariants 1 et 2, arbitrage Q9 |
| **P-04** | les deux verrous sont **deux** : sans `INPUT`, le fourre-tout de `FORWARD` ne rattrape rien | invariant 4 |
| **P-05** | le retrait enlève les règles, **conserve l'ipset**, et se rejoue | invariant 1 |
| **P-06** | ipset inutilisable : la sortie internet **ferme**, le hub-and-spoke tient — une panne d'outillage ne fait pas tomber l'invariant 2 | invariants 1 et 2 |
| **P-07** | reconstruction interrompue : le **barrage** reste, la fenêtre est fermée et non ouverte | invariant 2, arbitrage Q8 |
| **P-08** | le provisionnement **pose** le pare-feu public, il ne l'imprime pas | §2.2, arbitrage Q13 |

## Ce que P-03 rend visible, et ce qu'il ne peut pas rendre visible

Il rend visible **la moitié observable de Q9** : un kit → kit est refusé
**en silence** au bout du délai plein (DROP), un kit hors ipset est refusé
**explicitement** en quelques millisecondes (REJECT). C'est une vraie
différence, et le compteur dit en plus **quelle règle** a tranché.

Il ne rend PAS visible la **forme** du refus. Remesuré au lot 4 (noyau
6.18, `nc`, délai 4 s), un `-j REJECT` sans `--reject-with` est déjà
immédiat sur du trafic routé : les quatre formes de REJECT sont
indiscernables entre elles au chronomètre. La table du gabarit du lot 0
disait l'inverse ; elle a été corrigée, et l'arbitrage Q9 avec elle. Le
`--reject-with icmp-admin-prohibited` se tient donc **statiquement**, par
le `regle_presente` de **P-01** — c'est là, et là seulement, qu'un retrait
de l'option ferait rougir la recette.

## Reste à écrire

Le catalogue du gabarit prévoit P-01 à P-20. Les huit écrits ici couvrent
les invariants 1, 2 et 4, l'idempotence de l'invariant 8, et les
arbitrages Q8, Q9, Q10 et Q13. Les autres attendent ce qu'ils testent : la
rotation de clé partagée (§6.4), le retrait d'une passerelle (§6.2), et le
verrou v6 — qui appartient au provisionnement de l'hôte (§2.1, couvert par
C-08) plus qu'au conteneur.
