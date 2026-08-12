# `wg` — l'image unique des trois rôles

**Lot 2** (les trois rôles montent leurs interfaces), complété au **lot 4**
(les règles du rôle `passerelle`). Fait foi : **annexe 3 §3**, arch. §6.2,
annexe 2 §3.

Une seule image, le rôle en variable d'environnement
`WG_ROLE=serveur|passerelle|kit`. `wg-node`, `wg-gateway` et `wg-kit` ont
été fusionnés (rév. 16/17) : **une seule chaîne de construction
multi-arch, un seul jeu de tests, un condensat identique partout**. Ne
jamais la re-fragmenter par rôle (annexe 7 §1).

Base Debian slim épinglée : `wireguard-tools`, `iproute2`, `iptables`
(**backend nf_tables** — vérifié au démarrage, refus sinon : piège 9),
`ipset`, `conntrack`, plus `iputils-ping`, `curl`, `jq` pour le rôle kit.
`network_mode: host`, `cap_add: [NET_ADMIN, NET_RAW]`.

L'**union** des besoins vit dans l'image unique (annexe 7 §1). Côté kit,
« pas d'iptables » est une absence d'**usage**, pas de binaire (arbitrage
Q1, 12/08/2026) : le rôle kit **n'invoque jamais netfilter** — le cas
R-06 l'atteste statiquement, le NAT et le pare-feu appartiennent à
`reseau-hote` et `parefeu`.

L'entrypoint aiguille sur `WG_ROLE` (rôle inconnu → refus bruyant) et
pose deux gardes communes : backend nf_tables, et un `trap` qui redescend
les interfaces à l'arrêt (pas d'interface orpheline en netns hôte). Les
scripts de rôle sont sous `roles/` — `commun.sh` (montage idempotent par
`wg syncconf`, jamais down/up ; mort bruyante si une interface tombe, le
compose relance).

## Rôle `passerelle` (lot 4)

`wg-kits` (clé **partagée**, 51820, table de peers posée de l'extérieur)
et `wg-core` (clé propre au nœud, un seul peer : le serveur). Puis les
règles de l'annexe 3 §3.2 : le **DROP `wg-kits → wg-kits`**, le chemin
autorisé et le NAT vers `wg-core`, l'ipset `internet_ok` et sa sortie
publique, les deux `REJECT` finaux (`FORWARD` **et** `INPUT`). Boucle de
réaffirmation 30 s, `trap` de retrait, `iptables -w` partout, sonde de
santé (§3.3).

## Rôle `kit` (lot 2)

Configuration WireGuard (`0.0.0.0/0` **avec** `Table = off`, MTU 1360,
keepalive 25), **watchdog** (ping de `10.100.0.1` toutes les 30 s,
rotation dans `endpoints.txt`) et **agent d'enrôlement** : machine à états
USINE → NOMINAL → SUSPENDU, écriture de l'état local et des blocs `pki`,
`tls`, `registre` (annexe 2 §3.2, §3.3).

## Rôle `serveur` (lot 2)

Montage des interfaces seul : `10.100.0.1/24`, `ListenPort 51821`, un
`[Peer]` par passerelle et un pour la VM usine. **Aucun forwarding, aucun
NAT** — le serveur est une feuille.

## Ce qui ne se négocie pas

- **Le DROP `wg-kits → wg-kits` est le hub-and-spoke** (invariant 2) : les
  `AllowedIPs` filtrent la source, pas la destination. Le retirer
  transformerait le relais en commutateur entre 10 000 kits.
- **`FORWARD` et `INPUT` sont deux verrous distincts** (invariant 4) : le
  premier borne ce qu'un kit traverse, le second ce qu'il atteint **sur la
  passerelle**. Le pare-feu public de l'hôte ne rattrape pas l'oubli.
- **L'ipset `internet_ok` plafonne, elle n'aiguille pas** (invariant 1) :
  la vider « pour dépanner » ouvre l'Internet à toute la flotte.
- **`AllowedIPs = 0.0.0.0/0` va avec `Table = off`** côté kit — jamais
  l'un sans l'autre (piège 11).
- **L'agent d'enrôlement vit dans ce conteneur, en netns hôte** : le
  déplacer sur le bridge crée l'impasse du premier démarrage (piège 17).
- **Idempotence** : `iptables -C` puis pose, et une boucle réaffirme —
  Docker et les redémarrages repoussent les règles.

Recette : `tests/roles/` (R-01 … R-06, tranche 1 — les trois rôles
montent), `tests/netfilter/` (P-01 … P-20, lot 4) et
`tests/agent-enrolement/` (tranche 2).
