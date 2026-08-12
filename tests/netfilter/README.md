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
     ./tests/netfilter/lancer.sh --lot 4          # P-01 … P-05
sudo SMARTBUREAU_SERVER=… ./tests/netfilter/lancer.sh --cas P-03 --garder
```

Prérequis : **root**, `ip netns`, `iptables` (backend nf_tables), `ipset`,
et `nc` pour les cas qui injectent des paquets. Un prérequis manquant fait
un cas **sauté**, jamais vert.

## Les cinq cas

| Cas | Ce qu'il prouve | Source |
|---|---|---|
| **P-01** | à froid : les sept règles, et leur **ordre** — le fourre-tout en dernier, les trois ACCEPT avant lui | §3.2, arbitrage Q8 |
| **P-02** | trois poses ne posent qu'une fois ; la boucle rattrape une règle effacée par dockerd | §3.2, invariant 8 |
| **P-03** | **paquets réels** : kit ↔ kit refusé (et le compteur dit que c'est le DROP qui a tranché), kit → cœur permis, sortie internet **par ipset** dans les deux sens | invariants 1 et 2, arbitrage Q9 |
| **P-04** | les deux verrous sont **deux** : sans `INPUT`, le fourre-tout de `FORWARD` ne rattrape rien | invariant 4 |
| **P-05** | le retrait enlève les règles, **conserve l'ipset**, et se rejoue | invariant 1 |

## Ce que P-03 rend visible

L'arbitrage Q9 se lit dans la sortie du cas : un kit → kit est refusé
**en silence** au bout du délai plein (DROP), un kit hors ipset est refusé
**explicitement** en quelques millisecondes (`REJECT
--reject-with icmp-admin-prohibited`). Sans le `--reject-with`, les deux
produiraient le même silence — c'est ce que le gabarit du lot 0 avait
mesuré, et ce que l'arbitrage a corrigé.

## Reste à écrire

Le catalogue du gabarit prévoit P-01 à P-20. Les cinq écrits ici couvrent
les invariants 1, 2, 4 et 8 et les trois arbitrages du lot. Les autres
attendent ce qu'ils testent : la rotation de clé partagée (§6.4), le
retrait d'une passerelle (§6.2), et le verrou v6 — qui appartient au
provisionnement de l'hôte (§2.1, couvert par C-08) plus qu'au conteneur.
